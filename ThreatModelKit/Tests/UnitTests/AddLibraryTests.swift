import ArchitectureDSL
import Testing
import TestSupport
@testable import ThreatModelKit

@Suite("Adding and updating a library")
struct AddLibraryTests {
    private let acme = "library \"acme\" { }\n"
    private let repository = "github.com/acme/threat-elements"
    private let lockPath = "/project/threatmodel/library/library.lock.json"
    private let libraryPath = "/project/threatmodel/library/acme.lib"

    private func aProject() -> (InMemoryProject, FakeLibraryFetcher, AddLibrary, UpdateLibraries) {
        let projects = InMemoryProject()
        projects.put("system \"Payments\" { }", at: "/project/threatmodel/payments.arch")
        let fetcher = FakeLibraryFetcher()
        fetcher.put(["acme.lib": acme], repository: repository, tag: "v2.1.0")
        let add = AddLibrary(projects: projects, fetcher: fetcher, sources: HclLibrarySource())
        return (projects, fetcher, add, UpdateLibraries(projects: projects, adds: add))
    }

    @Test func writesTheFilesAndTheLockEntry() throws {
        let (projects, _, add, _) = aProject()

        let response = add.execute(
            AddLibraryRequest(root: "/project", repository: repository, tag: "v2.1.0")
        )

        #expect(response == .added(label: "acme", files: ["acme.lib"]))
        #expect(try projects.read(path: libraryPath) == acme)
        let lock = LibraryLock.read(try projects.read(path: lockPath))
        let entry = try #require(lock.library(labelled: "acme"))
        #expect(entry.repository == repository)
        #expect(entry.tag == "v2.1.0")
        #expect(entry.files == ["acme.lib": LibraryLock.checksum(acme)])
    }

    @Test func replacesTheEntryWhenTheProjectAlreadyHoldsThatRepository() throws {
        let (projects, fetcher, add, _) = aProject()
        fetcher.put(
            ["acme.lib": "library \"acme\" { name = \"Acme\" }\n"],
            repository: repository,
            tag: "v2.2.0"
        )
        _ = add.execute(AddLibraryRequest(root: "/project", repository: repository, tag: "v2.1.0"))

        _ = add.execute(AddLibraryRequest(root: "/project", repository: repository, tag: "v2.2.0"))

        let lock = LibraryLock.read(try projects.read(path: lockPath))
        #expect(lock.libraries.count == 1)
        #expect(lock.library(labelled: "acme")?.tag == "v2.2.0")
        #expect(try projects.read(path: libraryPath).contains("Acme"))
    }

    @Test func keepsAnotherLibraryTheProjectAlreadyHolds() throws {
        let (projects, fetcher, add, _) = aProject()
        fetcher.put(["beta.lib": "library \"beta\" { }\n"], repository: "other", tag: "v1")
        _ = add.execute(AddLibraryRequest(root: "/project", repository: repository, tag: "v2.1.0"))

        _ = add.execute(AddLibraryRequest(root: "/project", repository: "other", tag: "v1"))

        let lock = LibraryLock.read(try projects.read(path: lockPath))
        #expect(lock.libraries.map(\.label) == ["acme", "beta"])
    }

    @Test func refusesAFileThatDoesNotParseAndWritesNothing() {
        let (projects, fetcher, add, _) = aProject()
        fetcher.put(["broken.lib": "library \"acme\" { nonsense }"], repository: "r", tag: "v1")

        let response = add.execute(AddLibraryRequest(root: "/project", repository: "r", tag: "v1"))

        guard case .refused(let reason) = response else {
            Issue.record("a library that does not parse was added")
            return
        }
        #expect(reason.contains("broken.lib"))
        #expect(projects.text(at: "/project/threatmodel/library/broken.lib") == nil)
    }

    @Test func refusesTwoFilesThatCarryOneLabel() {
        let (_, fetcher, add, _) = aProject()
        fetcher.put(
            ["one.lib": "library \"acme\" { }\n", "two.lib": "library \"acme\" { }\n"],
            repository: "r",
            tag: "v1"
        )

        let response = add.execute(AddLibraryRequest(root: "/project", repository: "r", tag: "v1"))

        guard case .refused(let reason) = response else {
            Issue.record("two files with one label were added")
            return
        }
        #expect(reason.contains("acme"))
    }

    @Test func saysWhatTheFetchSaid() {
        let (_, _, add, _) = aProject()

        let response = add.execute(
            AddLibraryRequest(root: "/project", repository: repository, tag: "v9")
        )

        guard case .cannotFetch(let reason) = response else {
            Issue.record("an unknown tag was added")
            return
        }
        #expect(reason.contains("v9"))
    }

    @Test func updatesEveryLibraryAtItsRecordedTag() throws {
        let (projects, fetcher, add, update) = aProject()
        _ = add.execute(AddLibraryRequest(root: "/project", repository: repository, tag: "v2.1.0"))
        // The tag now points at different text, the way a moved tag would.
        fetcher.put(
            ["acme.lib": "library \"acme\" { name = \"Moved\" }\n"],
            repository: repository,
            tag: "v2.1.0"
        )

        let response = update.execute(UpdateLibrariesRequest(root: "/project", label: nil))

        #expect(response == .updated(labels: ["acme"]))
        #expect(try projects.read(path: libraryPath).contains("Moved"))
        #expect(LibraryLock.read(try projects.read(path: lockPath))
            .library(labelled: "acme")?.tag == "v2.1.0")
    }

    @Test func updatesOnlyTheLibraryItIsGiven() throws {
        let (projects, fetcher, add, update) = aProject()
        fetcher.put(["beta.lib": "library \"beta\" { }\n"], repository: "other", tag: "v1")
        _ = add.execute(AddLibraryRequest(root: "/project", repository: repository, tag: "v2.1.0"))
        _ = add.execute(AddLibraryRequest(root: "/project", repository: "other", tag: "v1"))
        fetcher.put(
            ["acme.lib": "library \"acme\" { name = \"Moved\" }\n"],
            repository: repository,
            tag: "v2.1.0"
        )

        let response = update.execute(UpdateLibrariesRequest(root: "/project", label: "acme"))

        #expect(response == .updated(labels: ["acme"]))
        #expect(try projects.read(path: libraryPath).contains("Moved"))
    }

    @Test func saysSoWhenTheProjectHoldsNoSuchLibrary() {
        let (_, _, _, update) = aProject()

        #expect(
            update.execute(UpdateLibrariesRequest(root: "/project", label: "acme"))
                == .noSuchLibrary
        )
    }

    @Test func updatesNothingWhenTheProjectHoldsNoLockFile() {
        let (_, _, _, update) = aProject()

        #expect(
            update.execute(UpdateLibrariesRequest(root: "/project", label: nil))
                == .updated(labels: [])
        )
    }
}
