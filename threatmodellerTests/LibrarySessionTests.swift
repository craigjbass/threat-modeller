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
