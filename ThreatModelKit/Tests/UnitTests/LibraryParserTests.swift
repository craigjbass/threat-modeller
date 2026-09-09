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

    @Test func refusesADuplicateTechnologyIdentifier() {
        let read = read("""
        library "acme" {
          technology "one" { name = "One" category = "monitoring" }
          technology "one" { name = "Two" category = "monitoring" }
        }
        """)

        #expect(read.source == nil)
        #expect(
            read.diagnostics.contains { $0.message == "the technology \"one\" is declared twice" }
        )
    }

    @Test func refusesADuplicateThreatIdentifier() {
        let read = read("""
        library "acme" {
          threat "t" { name = "One" severity = "high" }
          threat "t" { name = "Two" severity = "high" }
        }
        """)

        #expect(read.source == nil)
        #expect(read.diagnostics.contains { $0.message == "the threat \"t\" is declared twice" })
    }

    @Test func warnsAboutAThreatNothingCanRaise() throws {
        let read = read("""
        library "acme" {
          threat "orphan" { name = "Orphan" severity = "low" }
        }
        """)

        #expect(read.source != nil)
        let warning = try #require(read.diagnostics.first)
        #expect(warning.severity == .warning)
        #expect(
            warning.message
                == "no technology in this library names \"orphan\", so nothing raises it"
        )
    }

    @Test func doesNotWarnAboutAZoneThreat() {
        let read = read("""
        library "acme" {
          threat "everywhere" { name = "Everywhere" severity = "low" zone = true }
        }
        """)

        #expect(read.diagnostics.isEmpty)
    }

    @Test func doesNotWarnAboutAThreatATechnologyNames() {
        let read = read("""
        library "acme" {
          technology "t" { name = "T" category = "monitoring" threats = ["named"] }
          threat "named" { name = "Named" severity = "low" }
        }
        """)

        #expect(read.diagnostics.isEmpty)
    }

    @Test func reportsEveryFaultRatherThanTheFirst() {
        let read = read("""
        library "acme" {
          technology "one" { category = "monitoring" }
          threat "t" { name = "T" }
        }
        """)

        #expect(read.diagnostics.count == 2)
    }

    @Test func refusesAFileThatDoesNotStartWithLibrary() {
        let read = read("system \"Payments\" { }")

        #expect(read.source == nil)
        #expect(read.diagnostics.first?.message.contains("library") == true)
    }
}
