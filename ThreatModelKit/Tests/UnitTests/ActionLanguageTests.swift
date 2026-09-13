import Testing
import ArchitectureDSL
import ThreatModelKit

struct ActionLanguageTests {
    private func read(_ text: String) -> ArchitectureRead {
        HclArchitectureSource().read(text)
    }

    private let system = """
    system "Payments" {
      component "store" {
        technology = "aws-rds"
      }
      component "guard" {
        technology = "aws-ec2"
      }
      assumption "guard-not-deployed" {
        text = "The guard is bought and not deployed."
      }
      mitigates guard -> store {
        threats         = ["credential-theft"]
        reduces_risk_by = 60
        status          = "assumed"

        recommendation "adopt-the-guard" {
          text       = "Adopt the guard"
          note       = "It is bought and not deployed."
          blocked_by = "guard-not-deployed"
          sources    = ["https://example.com/ticket/1"]
        }
      }
    }
    """

    @Test func readsTheActionOnAnAssumedEdge() throws {
        let read = read(system)

        #expect(read.hasErrors == false)
        let edge = try #require(read.source?.mitigates.first)
        #expect(edge.action?.label == "adopt-the-guard")
        #expect(edge.action?.text == "Adopt the guard")
        #expect(edge.action?.note == "It is bought and not deployed.")
        #expect(edge.action?.blockedBy == "guard-not-deployed")
        #expect(edge.action?.sources == ["https://example.com/ticket/1"])
    }

    @Test func readsAnEdgeThatOnlyJoinsAnAction() throws {
        let read = read(system.replacingOccurrences(
            of: """
                recommendation "adopt-the-guard" {
                  text       = "Adopt the guard"
                  note       = "It is bought and not deployed."
                  blocked_by = "guard-not-deployed"
                  sources    = ["https://example.com/ticket/1"]
                }
            """,
            with: """
                recommendation "adopt-the-guard" {}
            """
        ))

        let edge = try #require(read.source?.mitigates.first)
        #expect(edge.action?.label == "adopt-the-guard")
        #expect(edge.action?.text == nil)
    }

    @Test func refusesAnAttributeAnActionDoesNotHold() {
        let read = read(system.replacingOccurrences(
            of: "note       = \"It is bought and not deployed.\"",
            with: "owner      = \"Platform team\""
        ))

        #expect(
            read.diagnostics.contains {
                $0.message == "a recommendation holds text, note, blocked_by and sources, not \"owner\""
            }
        )
    }

    @Test func readsAnEdgeWithNoActionAtAll() throws {
        let read = read("""
        system "Payments" {
          component "store" { technology = "aws-rds" }
          component "guard" { technology = "aws-ec2" }
          mitigates guard -> store {
            threats         = ["credential-theft"]
            reduces_risk_by = 60
          }
        }
        """)

        let edge = try #require(read.source?.mitigates.first)
        #expect(edge.action == nil)
    }
}
