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

    @Test func refusesAnActionThatJoinsWithNoText() throws {
        // A recommendation with an empty body names a label but states no
        // text for it. No other edge states text for this label either, so
        // the action drops under the same rule as refusesALabelNoEdgeStatesTextFor.
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

        #expect(read.diagnostics.contains { $0.message == "the action \"adopt-the-guard\" states no text" })
        let edge = try #require(read.source?.mitigates.first)
        #expect(edge.action == nil)
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

    @Test func refusesAnActionOnAnAdoptedEdge() throws {
        let read = read(system.replacingOccurrences(
            of: "status          = \"assumed\"",
            with: "status          = \"adopted\""
        ))

        #expect(
            read.diagnostics.contains {
                $0.message == "the mitigates edge \"guard->store\" is adopted, so it carries no recommendation"
            }
        )
        // The edge stands; only its action drops.
        let edge = try #require(read.source?.mitigates.first)
        #expect(edge.action == nil)
        #expect(edge.reducesRiskBy == 60)
    }

    @Test func refusesTwoEdgesStatingOneActionsTextAndKeepsTheFirst() throws {
        let read = read("""
        system "Payments" {
          component "store" { technology = "aws-rds" }
          component "queue" { technology = "aws-rds" }
          component "guard" { technology = "aws-ec2" }
          mitigates guard -> store {
            threats         = ["credential-theft"]
            reduces_risk_by = 60
            status          = "assumed"
            recommendation "adopt" { text = "Adopt the guard" }
          }
          mitigates guard -> queue {
            threats         = ["credential-theft"]
            reduces_risk_by = 40
            status          = "assumed"
            recommendation "adopt" { text = "Adopt it again" }
          }
        }
        """)

        #expect(read.diagnostics.contains { $0.message == "the action \"adopt\" states its text twice" })
        let edges = try #require(read.source?.mitigates)
        #expect(edges[0].action?.text == "Adopt the guard")
        #expect(edges[1].action == nil)
    }

    @Test func refusesALabelNoEdgeStatesTextFor() throws {
        // One line, not a multi-line literal: a multi-line literal's own
        // indentation stripping makes the match depend on how this file is
        // laid out rather than on what the fixture says.
        let read = read(system.replacingOccurrences(
            of: "      text       = \"Adopt the guard\"\n",
            with: ""
        ))

        #expect(read.diagnostics.contains { $0.message == "the action \"adopt-the-guard\" states no text" })
        let edge = try #require(read.source?.mitigates.first)
        #expect(edge.action == nil)
    }

    @Test func refusesAnEmptyText() throws {
        let read = read(system.replacingOccurrences(
            of: "text       = \"Adopt the guard\"",
            with: "text       = \"\""
        ))

        #expect(read.diagnostics.contains { $0.message == "the action \"adopt-the-guard\" has no text" })
        let edge = try #require(read.source?.mitigates.first)
        #expect(edge.action == nil)
    }

    @Test func refusesABlockerNoAssumptionDeclares() throws {
        let read = read(system.replacingOccurrences(
            of: "blocked_by = \"guard-not-deployed\"",
            with: "blocked_by = \"nobody-declares-this\""
        ))

        #expect(
            read.diagnostics.contains {
                $0.message == "the action \"adopt-the-guard\" is blocked by \"nobody-declares-this\", which no assumption declares"
            }
        )
        let edge = try #require(read.source?.mitigates.first)
        #expect(edge.action == nil)
    }

    @Test func joinsTwoEdgesUnderOneLabelWhenOnlyOneStatesText() throws {
        let read = read("""
        system "Payments" {
          component "store" { technology = "aws-rds" }
          component "queue" { technology = "aws-rds" }
          component "guard" { technology = "aws-ec2" }
          mitigates guard -> store {
            threats         = ["credential-theft"]
            reduces_risk_by = 60
            status          = "assumed"
            recommendation "adopt" { text = "Adopt the guard" }
          }
          mitigates guard -> queue {
            threats         = ["credential-theft"]
            reduces_risk_by = 40
            status          = "assumed"
            recommendation "adopt" {}
          }
        }
        """)

        #expect(read.diagnostics.isEmpty)
        let edges = try #require(read.source?.mitigates)
        #expect(edges[0].action?.text == "Adopt the guard")
        #expect(edges[1].action != nil)
        #expect(edges[1].action?.text == nil)
    }

    @Test func refusesAnActionTrippingTwoFaultsAndReportsOne() throws {
        let read = read(
            system
                .replacingOccurrences(of: "      text       = \"Adopt the guard\"\n", with: "")
                .replacingOccurrences(
                    of: "blocked_by = \"guard-not-deployed\"",
                    with: "blocked_by = \"nobody-declares-this\""
                )
        )

        #expect(
            read.diagnostics.contains {
                $0.message == "the action \"adopt-the-guard\" is blocked by \"nobody-declares-this\", which no assumption declares"
            }
        )
        #expect(read.diagnostics.contains { $0.message == "the action \"adopt-the-guard\" states no text" } == false)
        let edge = try #require(read.source?.mitigates.first)
        #expect(edge.action == nil)
    }
}
