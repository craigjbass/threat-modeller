import Testing
import ThreatModelKit
import TestSupport

/// Which tag is the newest.
@Suite("Comparing version tags")
struct TagVersionTests {
    @Test func comparesNumbersRatherThanText() {
        #expect(TagVersion.newest(of: ["v1", "v2", "v9", "v10"]) == "v10")
        #expect(TagVersion.newest(of: ["1.2.3", "1.10.0", "1.9.9"]) == "1.10.0")
    }

    @Test func aTagThatIsNotAVersionIsNeverTheNewest() {
        #expect(TagVersion("latest") == nil)
        #expect(TagVersion("v") == nil)
        #expect(TagVersion("release-candidate") == nil)
        #expect(TagVersion.newest(of: ["latest", "v1.0.0", "nightly"]) == "v1.0.0")
        #expect(TagVersion.newest(of: ["latest", "nightly"]) == nil)
    }

    /// A pre-release is not offered to a project running a release. A project
    /// already running one is offered a newer one.
    @Test func aPreReleaseIsOfferedOnlyToAProjectRunningOne() {
        let tags = ["v1.2.0", "v1.3.0-rc.1", "v1.3.0-rc.2"]

        #expect(TagVersion.newest(of: tags) == "v1.2.0")
        #expect(TagVersion.newest(of: tags, wantsPreRelease: true) == "v1.3.0-rc.2")
    }

    @Test func aReleaseIsNewerThanThePreReleaseItLeadsTo() {
        #expect(TagVersion.newest(of: ["v2.0.0-rc.1", "v2.0.0"], wantsPreRelease: true) == "v2.0.0")
    }

    @Test func aShorterVersionIsTheSameAsOneWithZeros() {
        #expect(TagVersion("v1.2") == TagVersion("v1.2"))
        #expect(TagVersion.newest(of: ["v1.2", "v1.2.1"]) == "v1.2.1")
        #expect(TagVersion.newest(of: ["v1.2", "v1.2.0"]) == "v1.2")
    }
}

/// What the outdated check asks the repository for.
@Suite("Reading what a library's newest tag is")
struct OutdatedLibraryTagTests {
    private func aProject(tags: [String], current: String = "v1.0.0") -> TestDependencies {
        let app = TestDependencies()
        app.project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        app.project.put(
            """
            {
              "version" : 1,
              "libraries" : {
                "acme" : {
                  "repository" : "/elements",
                  "tag" : "\(current)",
                  "files" : { "acme.lib" : "0" }
                }
              }
            }
            """,
            at: "/work/threatmodel/library/library.lock.json"
        )
        app.libraryFetcher.hold(tags: tags, at: "/elements")
        return app
    }

    private func listed(_ app: TestDependencies) -> [OutdatedLibrary] {
        guard case .listed(let libraries) = app.listOutdatedLibraries()
            .execute(ListOutdatedLibrariesRequest(root: "/work")) else { return [] }
        return libraries
    }

    @Test func reportsTheNewestVersionRatherThanTheLastByText() {
        let app = aProject(tags: ["v1", "v2", "v9", "v10"])

        #expect(listed(app).first?.newestTag == "v10")
    }

    @Test func asksForTheNewestTagRatherThanEveryTag() {
        let app = aProject(tags: ["v1.0.0", "v2.0.0"])

        _ = listed(app)

        #expect(app.libraryFetcher.newestTagReads == 1)
        #expect(app.libraryFetcher.tagReads == 0)
    }

    /// A repository with thousands of tags costs one call, whatever it holds.
    @Test func aRepositoryWithThousandsOfTagsCostsOneCall() {
        let many = (1 ... 5000).map { "v1.0.\($0)" }
        let app = aProject(tags: many)

        let libraries = listed(app)

        #expect(libraries.first?.newestTag == "v1.0.5000")
        #expect(app.libraryFetcher.newestTagReads == 1)
        #expect(app.libraryFetcher.tagReads == 0)
    }

    @Test func aProjectRunningAPreReleaseIsOfferedTheNewerPreRelease() {
        let app = aProject(tags: ["v1.0.0", "v2.0.0-rc.1"], current: "v2.0.0-rc.0")

        #expect(listed(app).first?.newestTag == "v2.0.0-rc.1")
    }
}
