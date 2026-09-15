import Foundation
import Testing
@testable import threatmodeller

/// The recent list is what lets a user open a project again without the panel.
/// These tests run over a defaults suite made for the test, so nothing they
/// write reaches the application's own defaults.
@MainActor
struct RecentProjectsTests {
    private func aStore(named name: String) -> RecentProjects {
        let suite = "recent-projects-test-\(name)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        return RecentProjects(defaults: defaults)
    }

    /// A directory this test made.
    private func aDirectory(_ name: String) -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("recent-projects-test", isDirectory: true)
            .appendingPathComponent(name, isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test func listsARecordedRoot() {
        let store = aStore(named: "one")
        let url = aDirectory("one")

        store.record(url: url)

        #expect(store.list().count == 1)
        #expect(store.list().first?.path == url.path)
    }

    @Test func recordsOneRootOnce() {
        let store = aStore(named: "two")
        let url = aDirectory("two")

        store.record(url: url)
        store.record(url: url)

        #expect(store.list().count == 1)
    }

    @Test func namesTheLastDirectoryOfThePath() {
        let store = aStore(named: "three")
        let url = aDirectory("three")

        store.record(url: url)

        #expect(store.list().first?.name == url.lastPathComponent)
    }

    @Test func keepsTenAtMost() {
        let store = aStore(named: "four")

        for index in 0..<12 {
            store.record(url: aDirectory("p\(index)"))
        }

        #expect(store.list().count == 10)
        #expect(store.list().first?.name == "p11")
    }

    @Test func opensARootItRecorded() throws {
        let store = aStore(named: "five")
        let url = aDirectory("five")
        store.record(url: url)

        let entry = try #require(store.list().first)

        #expect(store.resolve(entry)?.path == url.path)
    }

    /// The application is no longer sandboxed, so a path is the whole entry
    /// and a list written by an older version still reads.
    @Test func opensARootRecordedAsAPathAlone() throws {
        let suite = "recent-projects-test-six"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        let url = aDirectory("six")
        defaults.set([["path": url.path]], forKey: "recentProjects")
        let store = RecentProjects(defaults: defaults)

        let entry = try #require(store.list().first)

        #expect(entry.path == url.path)
        #expect(store.resolve(entry)?.path == url.path)
    }

    @Test func forgetsARootThatIsNoLongerThere() throws {
        let store = aStore(named: "seven")
        let url = aDirectory("seven")
        store.record(url: url)
        try FileManager.default.removeItem(at: url)

        let entry = try #require(store.list().first)

        #expect(store.resolve(entry) == nil)
        #expect(store.list().isEmpty)
    }

    @Test func saysWhetherARowStillOpens() {
        let store = aStore(named: "exists")
        let url = aDirectory("exists")
        store.record(url: url)
        let there = store.list()[0]

        #expect(store.exists(there))
        #expect(store.exists(RecentProject(path: "/no/such/project", name: "gone")) == false)
    }

    @Test func clearMenuEmptiesTheList() {
        let store = aStore(named: "clear")
        store.record(url: aDirectory("clear"))

        store.clear()

        #expect(store.list().isEmpty)
    }

    @Test func namesTheProjectAReopenWouldOpen() {
        let store = aStore(named: "most-recent")
        store.record(url: aDirectory("first"))
        store.record(url: aDirectory("second"))

        #expect(store.mostRecent()?.name == "second")
    }
}

/// What the application opens at launch.
@Suite("The launch choice")
struct LaunchChoiceTests {
    @Test func opensTheWelcomeWindowWhileTheSettingIsOff() {
        #expect(
            LaunchChoice.choose(
                commandLinePath: nil,
                reopensLastProject: false,
                lastProject: "/work",
                exists: { _ in true }
            ) == .welcome
        )
    }

    @Test func opensTheLastProjectWhenTheSettingIsOn() {
        #expect(
            LaunchChoice.choose(
                commandLinePath: nil,
                reopensLastProject: true,
                lastProject: "/work",
                exists: { _ in true }
            ) == .project(path: "/work")
        )
    }

    @Test func opensTheWelcomeWindowWhenTheLastProjectIsGone() {
        #expect(
            LaunchChoice.choose(
                commandLinePath: nil,
                reopensLastProject: true,
                lastProject: "/work",
                exists: { _ in false }
            ) == .welcome
        )
    }

    @Test func aPathOnTheCommandLineWinsOverTheSetting() {
        #expect(
            LaunchChoice.choose(
                commandLinePath: "/named",
                reopensLastProject: false,
                lastProject: "/work",
                exists: { _ in true }
            ) == .project(path: "/named")
        )
        #expect(
            LaunchChoice.choose(
                commandLinePath: "/named",
                reopensLastProject: true,
                lastProject: "/work",
                exists: { _ in true }
            ) == .project(path: "/named")
        )
    }

    @Test func opensTheWelcomeWindowWhenNothingWasEverOpened() {
        #expect(
            LaunchChoice.choose(
                commandLinePath: nil,
                reopensLastProject: true,
                lastProject: nil,
                exists: { _ in true }
            ) == .welcome
        )
    }
}
