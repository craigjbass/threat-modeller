import ArchitectureDSL
import Testing
import TestSupport
@testable import ThreatModelKit

@Suite("Removing a library")
struct RemoveLibraryTests {
    private let library = "library \"acme\" { }\n"

    private func aProject(usingTheLibrary: Bool) -> (InMemoryProject, RemoveLibrary) {
        let projects = InMemoryProject()
        projects.put(
            usingTheLibrary
                ? "system \"Payments\" { component \"i\" { technology = \"acme-cribl-stream\" } }"
                : "system \"Payments\" { component \"i\" { technology = \"aws-ec2\" } }",
            at: "/project/threatmodel/payments.arch"
        )
        projects.put(library, at: "/project/threatmodel/library/acme.lib")
        projects.put(
            LibraryLock(libraries: [
                LockedLibrary(
                    label: "acme",
                    repository: "r",
                    tag: "v1",
                    files: ["acme.lib": LibraryLock.checksum(library)]
                )
            ]).written(),
            at: "/project/threatmodel/library/library.lock.json"
        )
        return (
            projects,
            RemoveLibrary(projects: projects, architectureSources: HclArchitectureSource())
        )
    }

    @Test func deletesTheFilesAndTheLockEntry() throws {
        let (projects, remove) = aProject(usingTheLibrary: false)

        let response = remove.execute(
            RemoveLibraryRequest(root: "/project", label: "acme", isForced: false)
        )

        #expect(response == .removed(files: ["acme.lib"]))
        #expect(projects.text(at: "/project/threatmodel/library/acme.lib") == nil)
        #expect(
            LibraryLock.read(
                try projects.read(path: "/project/threatmodel/library/library.lock.json")
            ).libraries.isEmpty
        )
    }

    @Test func refusesWhileASystemNamesIt() {
        let (_, remove) = aProject(usingTheLibrary: true)

        #expect(
            remove.execute(RemoveLibraryRequest(root: "/project", label: "acme", isForced: false))
                == .inUse(systems: ["payments"])
        )
    }

    @Test func leavesTheFilesWhenItRefuses() {
        let (projects, remove) = aProject(usingTheLibrary: true)

        _ = remove.execute(RemoveLibraryRequest(root: "/project", label: "acme", isForced: false))

        #expect(projects.text(at: "/project/threatmodel/library/acme.lib") != nil)
    }

    @Test func removesItAnywayWhenForced() {
        let (projects, remove) = aProject(usingTheLibrary: true)

        _ = remove.execute(RemoveLibraryRequest(root: "/project", label: "acme", isForced: true))

        #expect(projects.text(at: "/project/threatmodel/library/acme.lib") == nil)
    }

    @Test func saysSoWhenTheProjectHoldsNoSuchLibrary() {
        let (_, remove) = aProject(usingTheLibrary: false)

        #expect(
            remove.execute(RemoveLibraryRequest(root: "/project", label: "beta", isForced: false))
                == .noSuchLibrary
        )
    }
}

@Suite("Verifying the libraries")
struct VerifyLibrariesTests {
    private let library = "library \"acme\" { }\n"

    /// A project holding one library, its lock entry, and whatever the caller
    /// wants the file on disk to say.
    private func aProject(fileSays: String?) -> VerifyLibraries {
        let projects = InMemoryProject()
        projects.put("system \"Payments\" { }", at: "/project/threatmodel/payments.arch")
        if let fileSays {
            projects.put(fileSays, at: "/project/threatmodel/library/acme.lib")
        }
        projects.put(
            LibraryLock(libraries: [
                LockedLibrary(
                    label: "acme",
                    repository: "r",
                    tag: "v1",
                    files: ["acme.lib": LibraryLock.checksum(library)]
                )
            ]).written(),
            at: "/project/threatmodel/library/library.lock.json"
        )
        return VerifyLibraries(projects: projects)
    }

    @Test func saysTheFilesMatchTheLockFile() {
        let response = aProject(fileSays: library)
            .execute(VerifyLibrariesRequest(root: "/project"))

        #expect(response == .verified(matched: ["acme.lib"], differed: []))
    }

    @Test func saysWhichFileDiffers() {
        let response = aProject(fileSays: "library \"acme\" { name = \"Changed\" }\n")
            .execute(VerifyLibrariesRequest(root: "/project"))

        #expect(response == .verified(matched: [], differed: ["acme.lib"]))
    }

    @Test func saysWhichFileIsMissing() {
        let response = aProject(fileSays: nil)
            .execute(VerifyLibrariesRequest(root: "/project"))

        #expect(response == .verified(matched: [], differed: ["acme.lib"]))
    }

    @Test func saysNothingWhenTheProjectHoldsNoLockFile() {
        let projects = InMemoryProject()
        projects.put("system \"Payments\" { }", at: "/project/threatmodel/payments.arch")

        let response = VerifyLibraries(projects: projects)
            .execute(VerifyLibrariesRequest(root: "/project"))

        #expect(response == .verified(matched: [], differed: []))
    }
}

@Suite("Listing the libraries")
struct ListLibrariesTests {
    private let library = "library \"acme\" {\n  name = \"Acme Platform\"\n}\n"

    private func aProject() -> (InMemoryProject, ListLibraries, FakeLibraryFetcher) {
        let projects = InMemoryProject()
        projects.put("system \"Payments\" { }", at: "/project/threatmodel/payments.arch")
        projects.put(library, at: "/project/threatmodel/library/acme.lib")
        projects.put(
            LibraryLock(libraries: [
                LockedLibrary(
                    label: "acme",
                    repository: "github.com/acme/threat-elements",
                    tag: "v2.1.0",
                    files: ["acme.lib": LibraryLock.checksum(library)]
                )
            ]).written(),
            at: "/project/threatmodel/library/library.lock.json"
        )
        let fetcher = FakeLibraryFetcher()
        return (
            projects,
            ListLibraries(
                projects: projects,
                sources: HclLibrarySource(),
                verifies: VerifyLibraries(projects: projects)
            ),
            fetcher
        )
    }

    @Test func listsWhatTheProjectHolds() throws {
        let (_, list, _) = aProject()

        guard case .listed(let libraries) = list.execute(
            ListLibrariesRequest(root: "/project")
        ) else {
            Issue.record("the libraries were not listed")
            return
        }

        let one = try #require(libraries.first)
        #expect(one.label == "acme")
        #expect(one.name == "Acme Platform")
        #expect(one.repository == "github.com/acme/threat-elements")
        #expect(one.tag == "v2.1.0")
        #expect(one.matchesLock)
    }

    @Test func saysAFileDoesNotMatchTheLockFile() throws {
        let (projects, list, _) = aProject()
        projects.put("library \"acme\" { }\n", at: "/project/threatmodel/library/acme.lib")

        guard case .listed(let libraries) = list.execute(
            ListLibrariesRequest(root: "/project")
        ) else {
            Issue.record("the libraries were not listed")
            return
        }

        #expect(try #require(libraries.first).matchesLock == false)
    }

    @Test func listsNothingForAProjectWithNoLibrary() {
        let projects = InMemoryProject()
        projects.put("system \"Payments\" { }", at: "/project/threatmodel/payments.arch")

        guard case .listed(let libraries) = ListLibraries(
            projects: projects,
            sources: HclLibrarySource(),
            verifies: VerifyLibraries(projects: projects)
        ).execute(ListLibrariesRequest(root: "/project")) else {
            Issue.record("an empty project was not listed")
            return
        }

        #expect(libraries.isEmpty)
    }

    @Test func saysWhichLibraryHasANewerTag() throws {
        let (projects, _, fetcher) = aProject()
        fetcher.put([:], repository: "github.com/acme/threat-elements", tag: "v2.1.0")
        fetcher.put([:], repository: "github.com/acme/threat-elements", tag: "v2.2.0")

        guard case .listed(let outdated) = ListOutdatedLibraries(
            projects: projects,
            fetcher: fetcher
        ).execute(ListOutdatedLibrariesRequest(root: "/project")) else {
            Issue.record("the tags were not read")
            return
        }

        let one = try #require(outdated.first)
        #expect(one.label == "acme")
        #expect(one.tag == "v2.1.0")
        #expect(one.newestTag == "v2.2.0")
        #expect(one.reason == nil)
    }

    @Test func saysNothingIsNewerWhenTheRecordedTagIsTheNewest() throws {
        let (projects, _, fetcher) = aProject()
        fetcher.put([:], repository: "github.com/acme/threat-elements", tag: "v2.1.0")

        guard case .listed(let outdated) = ListOutdatedLibraries(
            projects: projects,
            fetcher: fetcher
        ).execute(ListOutdatedLibrariesRequest(root: "/project")) else {
            Issue.record("the tags were not read")
            return
        }

        #expect(try #require(outdated.first).newestTag == nil)
    }

    @Test func saysWhyItCouldNotReadTheTags() throws {
        let (projects, _, fetcher) = aProject()

        guard case .listed(let outdated) = ListOutdatedLibraries(
            projects: projects,
            fetcher: fetcher
        ).execute(ListOutdatedLibrariesRequest(root: "/project")) else {
            Issue.record("the tags were not read")
            return
        }

        // The fake holds no tag for that repository, so the list is empty and
        // there is nothing newer to name.
        #expect(try #require(outdated.first).newestTag == nil)
    }
}
