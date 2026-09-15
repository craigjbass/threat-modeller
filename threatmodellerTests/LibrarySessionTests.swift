import Testing
import TestSupport
import ThreatModelKit
@testable import threatmodeller

/// What the Libraries sheet shows and does. Every test runs over a fake
/// fetcher, so none runs `git` or reaches a server.
@MainActor
struct LibrarySessionTests {
    private let repository = "github.com/acme/threat-elements"

    private func aSession(usingTheLibrary: Bool = false) -> (LibrarySession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(
            usingTheLibrary
                ? "system \"Payments\" { component \"i\" { technology = \"acme-thing\" } }"
                : "system \"Payments\" { }",
            at: "/work/threatmodel/payments.arch"
        )
        useCases.libraryFetcher.put(
            ["acme.lib": "library \"acme\" {\n  name = \"Acme Platform\"\n}\n"],
            repository: repository,
            tag: "v2.1.0"
        )
        return (LibrarySession(useCases: useCases, root: "/work", onChange: {}), useCases)
    }

    @Test func listsNothingForAProjectWithNoLibrary() {
        let (session, _) = aSession()

        session.reload()

        #expect(session.libraries.isEmpty)
        #expect(session.errorMessage == nil)
    }

    @Test func addsALibraryAndListsIt() async throws {
        let (session, _) = aSession()

        await session.add(repository: repository, tag: "v2.1.0")

        let one = try #require(session.libraries.first)
        #expect(one.label == "acme")
        #expect(one.name == "Acme Platform")
        #expect(one.repository == repository)
        #expect(one.tag == "v2.1.0")
        #expect(one.matchesLock)
        #expect(one.newestTag == nil)
        #expect(session.errorMessage == nil)
        #expect(session.isWorking == false)
    }

    @Test func tellsTheProjectToReloadAfterAnAdd() async {
        let useCases = TestDependencies()
        useCases.project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        useCases.libraryFetcher.put(
            ["acme.lib": "library \"acme\" { }\n"],
            repository: "r",
            tag: "v1"
        )
        var reloads = 0
        let session = LibrarySession(useCases: useCases, root: "/work", onChange: { reloads += 1 })

        await session.add(repository: "r", tag: "v1")

        #expect(reloads == 1)
    }

    @Test func saysWhatTheFetchSaid() async {
        let (session, _) = aSession()

        await session.add(repository: repository, tag: "v9")

        #expect(session.libraries.isEmpty)
        #expect(session.errorMessage?.isEmpty == false)
        #expect(session.isWorking == false)
    }

    @Test func saysSoWhenWhatItFetchedDoesNotParse() async {
        let (session, useCases) = aSession()
        useCases.libraryFetcher.put(
            ["bad.lib": "library \"x\" { nonsense }"],
            repository: "bad",
            tag: "v1"
        )

        await session.add(repository: "bad", tag: "v1")

        #expect(session.errorMessage?.contains("bad.lib") == true)
    }

    @Test func updatesALibraryAtItsRecordedTag() async throws {
        let (session, useCases) = aSession()
        await session.add(repository: repository, tag: "v2.1.0")
        useCases.libraryFetcher.put(
            ["acme.lib": "library \"acme\" {\n  name = \"Moved\"\n}\n"],
            repository: repository,
            tag: "v2.1.0"
        )

        await session.update(label: "acme")

        #expect(try #require(session.libraries.first).name == "Moved")
    }

    @Test func asksAgainBeforeRemovingALibraryASystemNames() async {
        let (session, _) = aSession(usingTheLibrary: true)
        await session.add(repository: repository, tag: "v2.1.0")

        session.remove(label: "acme", isForced: false)

        #expect(session.removalInUse == ["payments"])
        #expect(session.libraries.map(\.label) == ["acme"])
    }

    @Test func removesItWhenTheUserSaysSoAgain() async {
        let (session, _) = aSession(usingTheLibrary: true)
        await session.add(repository: repository, tag: "v2.1.0")
        session.remove(label: "acme", isForced: false)

        session.remove(label: "acme", isForced: true)

        #expect(session.libraries.isEmpty)
        #expect(session.removalInUse == nil)
    }

    @Test func removesALibraryNoSystemNames() async {
        let (session, _) = aSession()
        await session.add(repository: repository, tag: "v2.1.0")

        session.remove(label: "acme", isForced: false)

        #expect(session.libraries.isEmpty)
        #expect(session.removalInUse == nil)
    }

    @Test func saysWhichLibraryHasANewerTag() async throws {
        let (session, useCases) = aSession()
        await session.add(repository: repository, tag: "v2.1.0")
        useCases.libraryFetcher.put([:], repository: repository, tag: "v2.2.0")

        await session.checkForUpdates()

        #expect(try #require(session.libraries.first).newestTag == "v2.2.0")
        #expect(session.isWorking == false)
    }

    @Test func opensTheListWithoutReachingAServer() {
        let (session, useCases) = aSession()

        session.reload()

        #expect(useCases.libraryFetcher.fetched.isEmpty)
    }
}

/// Stopping a fetch that is waiting on a server.
@MainActor
@Suite("Cancelling a library fetch")
struct LibraryFetchCancelTests {
    private func aProject() -> (LibrarySession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        useCases.libraryFetcher.put(
            ["acme.lib": "library \"acme\" { name = \"Acme\" }"],
            repository: "/elements",
            tag: "v1.0.0"
        )
        let session = LibrarySession(
            useCases: useCases,
            root: "/work",
            onChange: {},
            fetcher: useCases.libraryFetcher
        )
        return (session, useCases)
    }

    @Test func cancelStopsAFetchThatIsWaiting() async throws {
        let (session, useCases) = aProject()
        // A backstop, not a delay: the fetch answers as soon as Cancel
        // arrives. It is long because a loaded machine can hold the main
        // actor for seconds, and a fetch that runs out of wait answers with
        // the files.
        useCases.libraryFetcher.waits = 120

        let fetch = Task { await session.add(repository: "/elements", tag: "v1.0.0") }
        // The window redraws while the fetch waits, so the session answers.
        while session.isWorking == false { await Task.yield() }
        session.cancel()
        await fetch.value

        #expect(useCases.libraryFetcher.cancels == 1)
        #expect(session.errorMessage == "the fetch was stopped")
        #expect(session.isWorking == false)
    }

    @Test func aCancelledFetchWritesNoLibraryAndNoLockEntry() async throws {
        let (session, useCases) = aProject()
        // A backstop, not a delay: the fetch answers as soon as Cancel
        // arrives. It is long because a loaded machine can hold the main
        // actor for seconds, and a fetch that runs out of wait answers with
        // the files.
        useCases.libraryFetcher.waits = 120

        let fetch = Task { await session.add(repository: "/elements", tag: "v1.0.0") }
        while session.isWorking == false { await Task.yield() }
        session.cancel()
        await fetch.value

        #expect(useCases.project.text(at: "/work/threatmodel/library/acme.lib") == nil)
        #expect(useCases.project.text(at: "/work/threatmodel/library/library.lock.json") == nil)
        #expect(session.libraries.isEmpty)
    }

    @Test func cancelDoesNothingWhileNoFetchRuns() {
        let (session, useCases) = aProject()

        session.cancel()

        #expect(useCases.libraryFetcher.cancels == 0)
    }

    @Test func aFetchNobodyCancelsStillArrives() async throws {
        let (session, useCases) = aProject()

        await session.add(repository: "/elements", tag: "v1.0.0")

        #expect(session.errorMessage == nil)
        #expect(useCases.project.text(at: "/work/threatmodel/library/acme.lib") != nil)
    }
}

/// Browsing the index from the Libraries sheet.
@MainActor
@Suite("Browsing the library index")
struct LibraryIndexBrowsingTests {
    private let index = """
    {
      "version": 1,
      "libraries": [
        {
          "label": "acme",
          "name": "Acme Platform",
          "description": "Acme's own services",
          "repository": "/elements",
          "tags": ["v1.0.0"]
        },
        {
          "label": "beta",
          "name": "Beta Tooling",
          "repository": "/beta"
        }
      ]
    }
    """

    private func aProject() -> (LibrarySession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        useCases.libraryIndex.put(index, at: ProjectConvention.defaultLibraryIndex)
        useCases.libraryFetcher.put(
            ["acme.lib": "library \"acme\" { name = \"Acme\" }"],
            repository: "/elements",
            tag: "v1.0.0"
        )
        let session = LibrarySession(
            useCases: useCases,
            root: "/work",
            onChange: {},
            fetcher: useCases.libraryFetcher
        )
        return (session, useCases)
    }

    @Test func nothingReadsTheIndexUntilAPersonAsks() {
        let (_, useCases) = aProject()

        #expect(useCases.libraryIndex.reads.isEmpty)
    }

    @Test func listsWhatTheIndexHolds() async {
        let (session, _) = aProject()

        await session.browseIndex()

        #expect(session.shownIndexed.map(\.label) == ["acme", "beta"])
    }

    @Test func narrowsTheListByTypedText() async {
        let (session, _) = aProject()
        await session.browseIndex()

        session.indexSearch = "beta"

        #expect(session.shownIndexed.map(\.label) == ["beta"])
    }

    @Test func addsALibraryWithNoRepositoryTypedByHand() async throws {
        let (session, useCases) = aProject()
        await session.browseIndex()
        let entry = try #require(session.shownIndexed.first)

        await session.add(indexed: entry)

        #expect(useCases.project.text(at: "/work/threatmodel/library/acme.lib") != nil)
        #expect(session.libraries.map(\.label) == ["acme"])
    }

    @Test func anEntryWithNoVersionAsksForOne() async throws {
        let (session, _) = aProject()
        await session.browseIndex()
        let entry = try #require(session.shownIndexed.last)

        await session.add(indexed: entry)

        #expect(session.errorMessage?.contains("states no version") == true)
    }

    /// A machine with no network says so, and the typed form still works.
    @Test func aMachineWithNoNetworkSaysSoAndTheTypedFormStillWorks() async throws {
        let (session, useCases) = aProject()
        useCases.libraryIndex.refuse(
            .cannotRead(reason: "fatal: unable to access: Could not resolve host"),
            at: ProjectConvention.defaultLibraryIndex
        )

        await session.browseIndex()
        #expect(session.errorMessage?.contains("Could not resolve host") == true)
        #expect(session.shownIndexed.isEmpty)

        await session.add(repository: "/elements", tag: "v1.0.0")

        #expect(useCases.project.text(at: "/work/threatmodel/library/acme.lib") != nil)
    }
}
