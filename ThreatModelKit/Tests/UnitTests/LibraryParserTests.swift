import Testing
import ThreatModelKit
@testable import ArchitectureDSL

@Suite("Parsing the library language")
struct LibraryParserTests {
    private func read(_ text: String) -> LibraryRead {
        let scanned = Lexer(text).scan()
        var parser = LibraryParser(tokens: scanned.tokens, faults: scanned.faults)
        return parser.parse()
    }

    @Test func readsALibraryWithOneTechnology() throws {
        let read = read("""
        library "acme" {
          name      = "Acme Platform"
          catalogue = "v1.0.1"

          technology "cribl-stream" {
            name        = "Cribl Stream"
            category    = "monitoring"
            description = "Observability pipeline"
            threats     = ["pipeline-tamper", "credential-theft"]
            encrypts    = true
          }
        }
        """)

        let source = try #require(read.source)
        #expect(read.diagnostics.isEmpty)
        #expect(source.label == "acme")
        #expect(source.displayName == "Acme Platform")
        #expect(source.catalogueTag == "v1.0.1")
        let technology = try #require(source.technologies.first)
        #expect(technology.id == "cribl-stream")
        #expect(technology.name == "Cribl Stream")
        #expect(technology.category == "monitoring")
        #expect(technology.description == "Observability pipeline")
        #expect(technology.threatIds == ["pipeline-tamper", "credential-theft"])
        #expect(technology.encrypts)
    }

    @Test func readsAThreatWithItsControls() throws {
        let read = read("""
        library "acme" {
          threat "pipeline-tamper" {
            name         = "Pipeline tampering"
            description  = "An attacker changes a pipeline."
            severity     = "high"
            stride       = ["tampering"]
            zone         = true
            zone_context = "Reachable only from the VPC."

            mitre "T1565" {
              name   = "Data Manipulation"
              tactic = "impact"
            }

            control "Sign pipeline configurations"
            control "Review every pipeline change"
          }
        }
        """)

        let source = try #require(read.source)
        let threat = try #require(source.threats.first)
        #expect(threat.id == "pipeline-tamper")
        #expect(threat.name == "Pipeline tampering")
        #expect(threat.description == "An attacker changes a pipeline.")
        #expect(threat.severityLabel == "high")
        #expect(threat.strideIds == ["tampering"])
        #expect(threat.isZoneThreat)
        #expect(threat.isConnectionThreat == false)
        #expect(threat.zoneContext == "Reachable only from the VPC.")
        #expect(
            threat.mitre
                == [SourceMitreTechnique(id: "T1565", name: "Data Manipulation", tactic: "impact")]
        )
        #expect(threat.controlDescriptions == [
            "Sign pipeline configurations",
            "Review every pipeline change"
        ])
    }

    @Test func refusesAFileThatDoesNotStartWithLibrary() {
        let read = read("system \"Payments\" { }")

        #expect(read.source == nil)
        #expect(read.diagnostics.first?.message.contains("library") == true)
    }
}
