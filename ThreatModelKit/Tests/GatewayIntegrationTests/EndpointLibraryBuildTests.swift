import Testing
import Foundation
import ThreatModelKit
import ArchitectureDSL
@testable import CatalogueGateways

/// Builds `libraries/endpoint.lib` against the real vendored taxonomy, the
/// one a user's project actually holds, rather than a test fixture.
struct EndpointLibraryBuildTests {
    private func text() throws -> String {
        let here = URL(fileURLWithPath: #filePath)
        let root = here.deletingLastPathComponent()   // GatewayIntegrationTests
            .deletingLastPathComponent()              // Tests
            .deletingLastPathComponent()              // ThreatModelKit
            .deletingLastPathComponent()              // the repository
        return try String(contentsOf: root.appending(path: "libraries/endpoint.lib"), encoding: .utf8)
    }

    @Test func theLibraryBuildsAgainstTheVendoredTaxonomy() throws {
        let source = try #require(HclLibrarySource().read(try text()).source)
        let taxonomy = try BundledTechnologyCatalogue().taxonomy()
        let built = Library.build(from: source, taxonomy: taxonomy)
        #expect(built.faults.isEmpty)
        let library = try #require(built.library)
        #expect(library.technologies.count >= 10)
        #expect(library.threats.count >= 10)
        #expect(library.pathwayMitigations.isEmpty == false)
    }
}
