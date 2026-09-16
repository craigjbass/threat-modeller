import CommandLineApplication
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// The window's check summary and `threatmodeller check` read one use case,
/// so the two say the same words about the same project. These tests hold the
/// lines the summary lists to the lines the verb prints.
@Suite("The window and check agree")
struct WindowCheckAgreementTests {
    /// The lines the window's summary lists: every finding, the tolerance
    /// line, and the all-answered line when a system passes.
    private func summaryLines(_ useCases: TestDependencies) throws -> [String] {
        let layout = try useCases.project.discover(root: "/work")
        return layout.systems.flatMap { system -> [String] in
            guard case .checked(let found) = useCases.checkSystem().execute(
                CheckSystemRequest(root: "/work", systemName: system.name)
            ) else { return [] }
            return found.findings.map(\.said)
                + [found.toleranceLine].compactMap(\.self)
                + (found.passes ? [found.allAnsweredLine] : [])
        }
    }

    private func check(_ useCases: TestDependencies) -> (code: Int32, lines: [String]) {
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: useCases.project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller", "check", "/work"], output: { lines.append($0) })
        return (code, lines)
    }

    /// A project that fails check in every category: a file that does not
    /// parse, an unanswered threat, a stale answer, a stale tree, an accepted
    /// risk with no owner, and a breached policy rule.
    private func aFailingProject() -> TestDependencies {
        let useCases = TestDependencies()
        useCases.project.put("system \"Broken\" {", at: "/work/threatmodel/broken.arch")
        useCases.project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }

              component "db" {
                technology = "aws-rds"
                data       = "restricted"
              }

              flow api -> db
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        useCases.project.put(
            """
            controls for "Payments" {
              threat "credential-theft" on component "api" {
                control "Enforce IMDSv2 to block SSRF-based credential theft" {
                  status = "accepted"
                }

                control "Use IAM roles with minimal permissions" {
                  status = "accepted"
                }
              }

              threat "sql-injection" on component "gone" {
                control "Use parameterised queries" {
                  status = "implemented"
                }
              }
            }

            """,
            at: "/work/threatmodel/payments.controls"
        )
        useCases.project.put(
            """
            attack_trees for "Payments" {
              tree "t" {
                goal "misconfiguration" on component "db"

                step "credential-theft" on component "gone"
              }
            }

            """,
            at: "/work/threatmodel/payments.attacktree"
        )
        useCases.project.put(
            """
            policy {
              system_requires_owner = true
            }
            """,
            at: "/work/threatmodel/policy.hcl"
        )
        return useCases
    }

    @Test func theSummaryListsTheLinesCheckPrintsForAFailingProject() throws {
        let useCases = aFailingProject()

        let printed = check(useCases)

        #expect(printed.code != 0)
        #expect(printed.lines.isEmpty == false)
        #expect(try summaryLines(useCases) == printed.lines)
    }

    @Test func theSummaryListsTheLinesCheckPrintsForAPassingProject() throws {
        let useCases = TestDependencies()
        useCases.project.put("system \"Payments\" { }\n", at: "/work/threatmodel/payments.arch")

        let printed = check(useCases)

        #expect(printed.code == 0)
        #expect(try summaryLines(useCases) == printed.lines)
        #expect(printed.lines.contains("payments: every threat is answered"))
    }

    /// The summary passes exactly when the verb exits 0.
    @Test func theSummaryFailsExactlyWhenCheckFails() throws {
        let useCases = aFailingProject()
        let layout = try useCases.project.discover(root: "/work")

        let passes = layout.systems.allSatisfy { system in
            guard case .checked(let found) = useCases.checkSystem().execute(
                CheckSystemRequest(root: "/work", systemName: system.name)
            ) else { return false }
            return found.passes
        }

        #expect(passes == false)
        #expect(check(useCases).code != 0)
    }
}
