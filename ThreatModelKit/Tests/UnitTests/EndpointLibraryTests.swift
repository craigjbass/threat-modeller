import Testing
import Foundation
import ThreatModelKit
import ArchitectureDSL
import TestSupport

struct EndpointLibraryTests {
    /// The file sits at the repository root, four directories above this
    /// source file.
    private func text() throws -> String {
        let here = URL(fileURLWithPath: #filePath)
        let root = here.deletingLastPathComponent()   // UnitTests
            .deletingLastPathComponent()              // Tests
            .deletingLastPathComponent()              // ThreatModelKit
            .deletingLastPathComponent()              // the repository
        return try String(contentsOf: root.appending(path: "libraries/endpoint.lib"), encoding: .utf8)
    }

    @Test func theLibraryReadsWithNoFault() throws {
        let read = HclLibrarySource().read(try text())
        #expect(read.diagnostics.isEmpty)
        let source = try #require(read.source)
        #expect(source.label == "endpoint")
    }

    @Test func theLibraryBuildsAgainstTheTaxonomy() throws {
        let source = try #require(HclLibrarySource().read(try text()).source)
        let built = Library.build(from: source, taxonomy: CatalogueFixture.taxonomy())
        #expect(built.faults.isEmpty)
        let library = try #require(built.library)
        #expect(library.technologies.count >= 10)
        #expect(library.threats.count >= 10)
        #expect(library.pathwayMitigations.isEmpty == false)
    }

    @Test func everyConnectionThreatStatesTheKindsItAppliesTo() throws {
        let source = try #require(HclLibrarySource().read(try text()).source)
        for threat in source.threats where threat.isConnectionThreat {
            #expect(threat.appliesTo.isEmpty == false || threat.boundary != nil)
        }
    }

    @Test func aRewriteOfTheLibraryProducesTheSameText() throws {
        let text = try text()
        let source = try #require(HclLibrarySource().read(text).source)
        #expect(HclLibrarySource().write(source) == text)
    }
}
