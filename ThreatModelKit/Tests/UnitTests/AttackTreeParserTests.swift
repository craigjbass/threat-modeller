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

    @Test(arguments: [
        (
            """
            trees for "P" { }
            """,
            "expected attack_trees, not \"trees\""
        ),
        (
            """
            attack_trees of "P" { }
            """,
            "expected for, not \"of\""
        ),
        (
            """
            attack_trees for "P" {
              tree "t" { goal "g" on component "c" step "s" on component "c" }
              tree "t" { goal "g" on component "c" step "s" on component "c" }
            }
            """,
            "the tree \"t\" is declared twice"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" { step "s" on component "c" }
            }
            """,
            "the tree \"t\" states no goal"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                goal "g" on component "c"
                goal "h" on component "c"
                step "s" on component "c"
              }
            }
            """,
            "the tree \"t\" states two goals; it states one"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" { goal "g" on component "c" }
            }
            """,
            "the tree \"t\" holds no steps"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                goal "g" on component "c"
                step "s" on component "c"
                step "u" on component "c"
              }
            }
            """,
            "the tree \"t\" holds two roots; it holds one"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                goal "g" on component "c"
                all_of { }
              }
            }
            """,
            "the all_of in the tree \"t\" holds nothing"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                goal "g" on component "c"
                step "s" on gateway "c"
              }
            }
            """,
            "a step is raised by a component, a zone or a flow, not \"gateway\""
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                goal "g" on component "c"
                step "s" component "c"
              }
            }
            """,
            "a step says what raises it: on component, on zone or on flow"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                raises_risk_by = 140
                goal "g" on component "c"
                step "s" on component "c"
              }
            }
            """,
            "raises_risk_by is 140; it runs from 0 to 100"
        ),
        (
            """
            attack_trees for "P" {
              tree "t" {
                owner = "Platform team"
                goal "g" on component "c"
                step "s" on component "c"
              }
            }
            """,
            "a tree holds name, description, raises_risk_by, goal, all_of, any_of and step, not \"owner\""
        ),
    ])
    func refusesTheFault(text: String, message: String) {
        #expect(errors(text).map(\.message).contains(message))
    }

    @Test func producesNoSourceWhenAFileHoldsAnError() {
        #expect(read("""
        attack_trees for "P" {
          tree "t" { step "s" on component "c" }
        }
        """).source == nil)
    }
}
