import Testing
import ThreatModelKit
import ArchitectureDSL
import TestSupport

struct LibraryVocabularyTests {
    private func read(_ text: String) -> LibraryRead {
        HclLibrarySource().read(text)
    }

    private let taxonomy = CatalogueFixture.taxonomy()

    @Test func aThreatStatesTheFlowKindsItAppliesTo() throws {
        let source = try #require(read("""
        library "endpoint" {
          threat "dylib-injection" {
            name       = "Dynamic library injection"
            severity   = "high"
            connection = true
            applies_to = ["file", "ipc"]
          }
        }
        """).source)
        #expect(source.threats.first?.appliesTo == ["file", "ipc"])
    }

    @Test func aZoneThreatStatesItsBoundary() throws {
        let source = try #require(read("""
        library "endpoint" {
          threat "privilege-escalation" {
            name     = "Privilege escalation"
            severity = "critical"
            zone     = true
            boundary = "privilege"
          }
        }
        """).source)
        #expect(source.threats.first?.boundary == "privilege")
    }

    @Test func aThreatStatesThePrivilegeLevelsAndThatItIsAPathway() throws {
        let source = try #require(read("""
        library "endpoint" {
          threat "raw-device-read" {
            name     = "Raw device read"
            severity = "critical"
            runs_as  = ["root", "kernel"]
            pathway  = true
          }
        }
        """).source)
        #expect(source.threats.first?.runsAs == ["root", "kernel"])
        #expect(source.threats.first?.isPathwayThreat == true)
    }

    @Test func aLibraryDefinesAPathwayMitigation() throws {
        let source = try #require(read("""
        library "endpoint" {
          mitigation "es-client" {
            name            = "Endpoint Security client"
            description     = "Denies unsigned code"
            mitigates       = ["dylib-injection"]
            provided_by     = ["es"]
            reduces_risk_by = 60
          }
        }
        """).source)
        let mitigation = try #require(source.mitigations.first)
        #expect(mitigation.id == "es-client")
        #expect(mitigation.mitigatesThreatIds == ["dylib-injection"])
        #expect(mitigation.technologyIds == ["es"])
        #expect(mitigation.reducesRiskBy == 60)
    }

    @Test func theBuildPrefixesTheMitigationAndItsTechnologies() throws {
        let source = try #require(read("""
        library "endpoint" {
          technology "es" {
            name     = "Endpoint Security client"
            category = "compute"
          }

          threat "dylib-injection" {
            name       = "Dynamic library injection"
            severity   = "high"
            connection = true
            applies_to = ["file"]
          }

          mitigation "es-client" {
            name            = "Endpoint Security client"
            mitigates       = ["dylib-injection"]
            provided_by     = ["es"]
            reduces_risk_by = 60
          }
        }
        """).source)
        let built = Library.build(from: source, taxonomy: taxonomy)
        let library = try #require(built.library)
        #expect(built.faults.isEmpty)
        #expect(library.threats.first?.appliesToFlowKinds == [.file])
        let mitigation = try #require(library.pathwayMitigations.first)
        #expect(mitigation.id == PathwayMitigationId("endpoint-es-client"))
        #expect(mitigation.mitigatesThreatIds == [ThreatId("endpoint-dylib-injection")])
        #expect(mitigation.technologyIds == [TechnologyId("endpoint-es")])
    }

    @Test func aFlowKindTheApplicationDoesNotHoldIsAFault() throws {
        let source = try #require(read("""
        library "endpoint" {
          threat "t" {
            name       = "T"
            severity   = "high"
            applies_to = ["carrier-pigeon"]
          }
        }
        """).source)
        let built = Library.build(from: source, taxonomy: taxonomy)
        #expect(built.library == nil)
        #expect(built.faults.contains { $0.message.contains("carrier-pigeon") })
    }

    @Test func theMergedCatalogueOffersTheLibrarysMitigations() throws {
        let source = try #require(read("""
        library "endpoint" {
          mitigation "es-client" {
            name            = "Endpoint Security client"
            mitigates       = ["dylib-injection"]
            provided_by     = ["es"]
            reduces_risk_by = 60
          }
        }
        """).source)
        let library = try #require(Library.build(from: source, taxonomy: taxonomy).library)
        let merged = MergedCatalogue(base: CatalogueFixture.catalogue(), store: LibraryStore([library]))
        #expect(merged.pathwayMitigations().count == CatalogueFixture.pathwayMitigations().count + 1)
    }
}
