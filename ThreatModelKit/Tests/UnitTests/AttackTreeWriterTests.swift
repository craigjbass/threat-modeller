import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit

@Suite("Writing the attack tree language")
struct AttackTreeWriterTests {
    private let gateway = HclAttackTreeSource()

    private let canonical = """
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

    """

    @Test func writesAnUnchangedSourceWithNoDiff() throws {
        let read = try #require(gateway.read(canonical).source)

        #expect(gateway.write(read) == canonical)
    }

    @Test func writesAChainInTheOrderItWasRead() throws {
        let chain = """
        attack_trees for "P" {
          tree "t" {
            goal "g" on component "c"

            then {
              step "steal-x" on component "x"
              step "break-y" on component "y"
              step "use-y" on component "y"
            }
          }
        }

        """
        let read = try #require(gateway.read(chain).source)

        #expect(gateway.write(read) == chain)
    }

    private static let golden = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Goldens")
        .appendingPathComponent("chain.attacktree")

    /// The golden holds a chain with a note, a chain as one child of an
    /// `all_of`, and a branch beside it. Reading it and writing it changes
    /// no byte.
    @Test func theChainGoldenReadsAndWritesByteForByte() throws {
        let text = try String(contentsOf: Self.golden, encoding: .utf8)
        let read = gateway.read(text)

        #expect(read.hasErrors == false)
        #expect(gateway.write(try #require(read.source)) == text)
    }

    @Test func writesNoAttributeHoldingItsDefault() throws {
        let source = AttackTreeSource(
            systemName: "P",
            trees: [
                SourceAttackTree(
                    id: "t",
                    goal: SourceTreeTarget(threatId: "g", sourceKind: "component", sourceId: "c"),
                    root: .step(SourceTreeStep(target: SourceTreeTarget(
                        threatId: "s", sourceKind: "component", sourceId: "c"
                    )))
                ),
            ]
        )

        #expect(gateway.write(source) == """
        attack_trees for "P" {
          tree "t" {
            goal "g" on component "c"

            step "s" on component "c"
          }
        }

        """)
    }
}
