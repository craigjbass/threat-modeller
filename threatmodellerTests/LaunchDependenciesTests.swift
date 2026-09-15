import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The graph the application launches on.
@MainActor
@Suite("What a launch builds")
struct LaunchDependenciesTests {
    @Test func buildsTheDependenciesOnceForBothWindows() {
        var builds = 0

        let launch = LaunchDependencies {
            builds += 1
            return TestDependencies()
        }

        // Both windows read from it: the project window takes the use cases
        // and the About window takes the catalogue.
        #expect(launch.useCases != nil)
        #expect(launch.catalogue != nil)
        #expect(builds == 1)
    }

    /// The vendored catalogue is parsed once, because the graph that parses it
    /// is built once.
    @Test func parsesTheVendoredCatalogueOnce() throws {
        var builds = 0

        let launch = LaunchDependencies {
            builds += 1
            return try Dependencies()
        }

        let version = try #require(launch.catalogue)
        #expect(version.technologyCount > 0)
        #expect(builds == 1)
    }

    @Test func saysNothingIsThereWhenTheGraphCannotBeBuilt() {
        struct NoCatalogue: Error {}

        let launch = LaunchDependencies { throw NoCatalogue() }

        #expect(launch.useCases == nil)
        #expect(launch.catalogue == nil)
    }
}
