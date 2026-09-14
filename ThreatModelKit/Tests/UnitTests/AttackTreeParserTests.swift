import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("Parsing the attack tree language")
struct AttackTreeParserTests {
    private let gateway = HclAttackTreeSource()

    private func read(_ text: String) -> AttackTreeRead { gateway.read(text) }

    private func errors(_ text: String) -> [Diagnostic] {
        read(text).diagnostics.filter { $0.severity == .error }
    }

    @Test func readsAFileWithOneTree() throws {
        let read = read("""
        attack_trees for "Two-Tier Web Application" {
          catalogue = "v1.0.1"

          tree "read-every-customer-record" {
            name           = "Read every customer record"
            description    = "An unauthenticated caller reaches the customer table."
            raises_risk_by = 40

            goal "data-exfiltration" on component "db"

            all_of {
              step "ssrf-attack" on component "appserver" {
                note = "The avatar import fetches a URL the user gives it."
              }

              any_of {
                step "credential-theft" on component "appserver"

                all_of {
                  step "excessive-permissions" on component "secrets"
                  step "privilege-escalation" on component "secrets"
                }
              }
            }
          }
        }
        """)

        let source = try #require(read.source)
        #expect(read.diagnostics.isEmpty)
        #expect(source.systemName == "Two-Tier Web Application")
        #expect(source.catalogueTag == "v1.0.1")

        let tree = try #require(source.trees.first)
        #expect(tree.id == "read-every-customer-record")
        #expect(tree.name == "Read every customer record")
        #expect(tree.raisesRiskBy == 40)
        #expect(tree.goal == SourceTreeTarget(
            threatId: "data-exfiltration", sourceKind: "component", sourceId: "db"
        ))
        #expect(tree.steps.map(\.target.threatId) == [
            "ssrf-attack", "credential-theft", "excessive-permissions", "privilege-escalation",
        ])
        #expect(tree.steps.first?.note == "The avatar import fetches a URL the user gives it.")
    }

    @Test func readsAStepWithNoBodyAsAStepWithAnEmptyBody() throws {
        let read = read("""
        attack_trees for "P" {
          tree "t" {
            goal "data-exfiltration" on component "db"
            step "ssrf-attack" on component "appserver"
          }
        }
        """)

        let tree = try #require(read.source?.trees.first)
        #expect(tree.steps.count == 1)
        #expect(tree.steps[0].note == nil)
        #expect(tree.raisesRiskBy == 0)
    }

    @Test func readsAFlowStep() throws {
        let read = read("""
        attack_trees for "P" {
          tree "t" {
            goal "data-exfiltration" on component "db"
            step "connection-mitm" on flow "cdn->api"
          }
        }
        """)

        let tree = try #require(read.source?.trees.first)
        #expect(tree.steps[0].target.sourceKind == "flow")
        #expect(tree.steps[0].target.sourceId == "cdn->api")
    }
}
