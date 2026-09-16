import ArchitectureDSL
import CommandLineApplication
import Testing
import ThreatModelKit
import TestSupport

/// Issue #144. A `.governance` file written before the key fix holds two
/// blocks with one key. The parser refuses the whole file, so the window
/// refuses the system and the owners inside it are unread. The repair merges
/// those blocks and keeps every attribute a person wrote.
@Suite("Repairing a governance file the parser refuses")
struct GovernanceRepairTests {
    private let source = HclGovernanceSource()

    /// The file a save wrote before the fix: one fresh block with an empty
    /// stanza, and one stale block holding the owner and the dates.
    private let refused = """
    governance for "Payments" {
      threat "connection-mitm" on flow "api->db" {
        accepted "Enforce TLS" {
        }

        work "Write the runbook" {
        }
      }

      stale threat "connection-mitm" on flow "api->db" {
        stale accepted "Enforce TLS" {
          owner       = "Head of Platform"
          accepted_on = "2026-01-05"
          review_by   = "2026-07-05"
          rationale   = "the link runs inside one account"
          sources     = ["https://example.com/risk-register/RSK-9"]
        }

        stale work "Write the runbook" {
          owner      = "Platform team"
          effort     = "medium"
          due_by     = "2026-11-30"
          status     = "in_progress"
          acceptance = "The runbook names the owner."
          note       = "The rollout waits on the migration."
        }
      }
    }

    """

    @Test func theParserRefusesTheFileAsItStands() {
        #expect(
            source.read(refused).diagnostics.map(\.message)
                == ["connection-mitm@connection:api->db is governed twice"]
        )
    }

    @Test func theRepairWritesAFileTheParserReads() throws {
        guard case .repaired(let text, let merged) = source.repair(refused) else {
            Issue.record("the repair did not repair: \(source.repair(refused))")
            return
        }

        #expect(merged == ["connection-mitm@connection:api->db"])
        let read = source.read(text)
        #expect(read.diagnostics.map(\.message) == [], "the repair wrote:\n\(text)")
        _ = try #require(read.source)
    }

    @Test func theRepairKeepsEveryAttributeAPersonWrote() throws {
        guard case .repaired(let text, _) = source.repair(refused) else {
            Issue.record("the repair did not repair")
            return
        }
        let governance = try #require(source.read(text).source)

        #expect(governance.threats.count == 1)
        let threat = try #require(governance.threats.first)
        // The architecture still raises the threat, so the merged block is
        // not stale: one of the two blocks was not stale.
        #expect(threat.isStale == false)

        let risk = try #require(threat.accepted.first)
        #expect(risk.control == "Enforce TLS")
        #expect(risk.owner == "Head of Platform")
        #expect(risk.acceptedOn == "2026-01-05")
        #expect(risk.reviewBy == "2026-07-05")
        #expect(risk.rationale == "the link runs inside one account")
        #expect(risk.sources == ["https://example.com/risk-register/RSK-9"])
        #expect(risk.isStale == false)

        let work = try #require(threat.work.first)
        #expect(work.label == "Write the runbook")
        #expect(work.owner == "Platform team")
        #expect(work.effort == "medium")
        #expect(work.dueBy == "2026-11-30")
        #expect(work.status == "in_progress")
        #expect(work.acceptance == "The runbook names the owner.")
        #expect(work.note == "The rollout waits on the migration.")
        #expect(work.isStale == false)
    }

    /// Two blocks that are both stale merge into one stale block.
    @Test func theRepairKeepsABlockStaleWhenEveryBlockWithThatKeyIsStale() throws {
        let bothStale = """
        governance for "Payments" {
          stale threat "t" on component "api" {
            stale accepted "c" {
              owner = "Head of Platform"
            }
          }

          stale threat "t" on component "api" {
            stale accepted "c" {
              review_by = "2026-07-05"
            }
          }
        }
        """

        guard case .repaired(let text, _) = source.repair(bothStale) else {
            Issue.record("the repair did not repair")
            return
        }
        let governance = try #require(source.read(text).source)
        let threat = try #require(governance.threats.first)

        #expect(threat.isStale)
        let risk = try #require(threat.accepted.first)
        #expect(risk.isStale)
        #expect(risk.owner == "Head of Platform")
        #expect(risk.reviewBy == "2026-07-05")
    }

    /// Two actions of one label merge the same way.
    @Test func theRepairMergesTwoActionsOfOneLabel() throws {
        let twice = """
        governance for "Payments" {
          action "reenable-devtool-rules" {
            owner = "Endpoint team"
          }

          stale action "reenable-devtool-rules" {
            due_by = "2026-10-15"
          }
        }
        """

        guard case .repaired(let text, let merged) = source.repair(twice) else {
            Issue.record("the repair did not repair")
            return
        }
        let governance = try #require(source.read(text).source)
        let action = try #require(governance.actions.first)

        #expect(merged == ["reenable-devtool-rules"])
        #expect(governance.actions.count == 1)
        #expect(action.owner == "Endpoint team")
        #expect(action.dueBy == "2026-10-15")
        #expect(action.isStale == false)
    }

    @Test func aFileTheParserReadsNeedsNoRepair() {
        let fine = """
        governance for "Payments" {
          threat "t" on component "api" {
            accepted "c" {
              owner = "Head of Platform"
            }
          }
        }
        """

        #expect(source.repair(fine) == .notNeeded)
    }

    /// A fault a merge does not fix is left for a person to read.
    @Test func aFileThatFailsForAnotherReasonIsNotRepaired() {
        let wrong = """
        governance for "Payments" {
          threat "t" on vendor "api" {
            accepted "c" {
              review_by = "not a date"
            }
          }
        }
        """

        guard case .cannotRepair(let diagnostics) = source.repair(wrong) else {
            Issue.record("the repair changed a file it does not understand")
            return
        }
        #expect(diagnostics.contains { $0.message.contains("not \"vendor\"") })
    }
}

/// `threatmodeller format` is the way back for a person whose project stopped
/// opening: it rewrites the `.governance` file into the shape the parser
/// reads.
@Suite("Formatting a governance file from a shell")
struct GovernanceFormatTests {
    private let project = InMemoryProject(root: "/work")

    private func run(_ words: String...) -> (code: Int32, lines: [String]) {
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller"] + words, output: { lines.append($0) })
        return (code, lines)
    }

    private let architecture = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "db" {
        technology = "aws-rds"
        data       = "confidential"
      }

      flow api -> db
    }

    """

    private let refused = """
    governance for "Payments" {
      threat "connection-mitm" on flow "api->db" {
        accepted "Enforce TLS" {
        }
      }

      stale threat "connection-mitm" on flow "api->db" {
        stale accepted "Enforce TLS" {
          owner     = "Head of Platform"
          review_by = "2026-07-05"
        }
      }
    }

    """

    @Test func formatRepairsAGovernanceFileTheParserRefuses() throws {
        project.put(architecture, at: "/work/threatmodel/payments.arch")
        project.put(refused, at: "/work/threatmodel/payments.governance")

        let (code, lines) = run("format", "/work")

        #expect(code == 0, "format printed: \(lines.joined(separator: "\n"))")
        #expect(lines.contains { $0.contains("repaired") })
        #expect(
            lines.contains {
                $0.contains("merged the two blocks governing connection-mitm@connection:api->db")
            }
        )

        let written = try #require(project.text(at: "/work/threatmodel/payments.governance"))
        let read = HclGovernanceSource().read(written)
        #expect(read.diagnostics.map(\.message) == [], "format wrote:\n\(written)")
        let source = try #require(read.source)
        let risk = try #require(source.threats.first?.accepted.first)
        #expect(risk.owner == "Head of Platform")
        #expect(risk.reviewBy == "2026-07-05")
    }

    /// The repaired file is a file the window opens.
    @Test func theSystemOpensAfterTheFormat() throws {
        let app = TestDependencies()
        app.project.put(architecture, at: "/work/threatmodel/payments.arch")
        app.project.put(refused, at: "/work/threatmodel/payments.governance")

        let before = app.openSystem().execute(
            OpenSystemRequest(root: "/work", systemName: "payments")
        )
        guard case .refused(let fileName, let diagnostics) = before else {
            Issue.record("the system opened before the repair: \(before)")
            return
        }
        #expect(fileName == "payments.governance")
        #expect(
            diagnostics.map(\.message)
                == ["connection-mitm@connection:api->db is governed twice"]
        )

        var lines: [String] = []
        _ = CommandLineApplication(
            projects: app.project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller", "format", "/work"], output: { lines.append($0) })

        let after = app.openSystem().execute(
            OpenSystemRequest(root: "/work", systemName: "payments")
        )
        guard case .opened = after else {
            Issue.record("the system did not open after the repair: \(after)")
            return
        }
    }

    @Test func formatLeavesAGovernanceFileTheParserReadsInTheCanonicalShape() throws {
        project.put(architecture, at: "/work/threatmodel/payments.arch")
        project.put("""
        governance for "Payments" {
        threat "connection-mitm" on flow "api->db" {
        accepted "Enforce TLS" {
        owner = "Head of Platform"
        }
        }
        }
        """, at: "/work/threatmodel/payments.governance")

        let (code, _) = run("format", "/work")
        let written = try #require(project.text(at: "/work/threatmodel/payments.governance"))

        #expect(code == 0)
        #expect(written.contains("  threat \"connection-mitm\" on flow \"api->db\" {"))
        #expect(written.contains("      owner = \"Head of Platform\""))

        // A second format writes the same bytes.
        _ = run("format", "/work")
        #expect(project.text(at: "/work/threatmodel/payments.governance") == written)
    }
}
