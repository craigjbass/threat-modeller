import AppKit
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The check summary: the answer `threatmodeller check` gives, readable in
/// the window. One state, one list of everything the verb would print.
@MainActor
struct CheckSummaryTests {
    private func aSession(_ files: [String: String]) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        for (path, text) in files {
            useCases.project.put(text, at: path)
        }
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func findings(of session: ProjectSession) -> [CheckFinding] {
        session.checkedSystems.flatMap(\.findings)
    }

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    // MARK: one state for the whole project

    @Test func saysAProjectWithNothingToAnswerPassesCheck() async {
        let (session, _) = await aSession([
            "/work/threatmodel/payments.arch": "system \"Payments\" { }\n"
        ])

        #expect(session.passesCheck)
        #expect(session.checkFailureCount == 0)
        #expect(findings(of: session).isEmpty)
        #expect(session.checkedSystems.map(\.name) == ["payments"])
    }

    @Test func saysAProjectWithAnUnansweredThreatFailsCheck() async {
        let (session, _) = await aSession(["/work/threatmodel/payments.arch": payments])

        #expect(session.passesCheck == false)
        #expect(session.checkFailureCount > 0)
    }

    // MARK: one finding per category, in the words check prints

    @Test func listsAParseDiagnostic() async {
        let (session, _) = await aSession([
            "/work/threatmodel/broken.arch": "system \"Broken\" {"
        ])

        #expect(session.passesCheck == false)
        let diagnostic = findings(of: session).first { $0.category == .diagnostic }
        #expect(diagnostic?.said.hasPrefix("/work/threatmodel/broken.arch:") == true)
    }

    @Test func listsAnUnansweredThreat() async {
        let (session, _) = await aSession(["/work/threatmodel/payments.arch": payments])

        let unanswered = findings(of: session).filter { $0.category == .unanswered }
        #expect(
            unanswered.contains {
                $0.said.contains("credential-theft on component \"api\"")
                    && $0.said.contains("has no answer")
            }
        )
    }

    @Test func listsAStaleAnswer() async {
        let (session, _) = await aSession([
            "/work/threatmodel/payments.arch": payments,
            "/work/threatmodel/payments.controls": """
            controls for "Payments" {
              threat "sql-injection" on component "gone" {
                control "Use parameterised queries" {
                  status = "implemented"
                }
              }
            }

            """
        ])

        let stale = findings(of: session).filter { $0.category == .stale }
        #expect(
            stale.map(\.said) == [
                "/work/threatmodel/payments.controls: sql-injection@component:gone"
                    + " is answered but no longer raised"
            ]
        )
    }

    @Test func listsAStaleAttackTree() async {
        let (session, _) = await aSession([
            "/work/threatmodel/payments.arch": payments,
            "/work/threatmodel/payments.attacktree": """
            attack_trees for "Payments" {
              tree "t" {
                goal "misconfiguration" on component "api"

                step "credential-theft" on component "gone"
              }
            }

            """
        ])

        let trees = findings(of: session).filter { $0.category == .staleTree }
        #expect(
            trees.map(\.said) == [
                "/work/threatmodel/payments.controls: "
                    + "the tree \"t\" is written but no longer binds"
            ]
        )
    }

    @Test func listsAGovernanceFailure() async {
        let (session, _) = await aSession([
            "/work/threatmodel/payments.arch": payments,
            "/work/threatmodel/payments.controls": """
            controls for "Payments" {
              threat "credential-theft" on component "api" {
                control "Enforce IMDSv2 to block SSRF-based credential theft" {
                  status = "accepted"
                }

                control "Use IAM roles with minimal permissions" {
                  status = "accepted"
                }
              }
            }

            """
        ])

        let governance = findings(of: session).filter { $0.category == .governance }
        #expect(
            governance.contains {
                $0.said.contains(
                    "credential-theft@component:api is accepted and has no governance entry"
                )
            }
        )
    }

    @Test func listsAPolicyBreach() async {
        let (session, _) = await aSession([
            "/work/threatmodel/payments.arch": payments,
            "/work/threatmodel/policy.hcl": """
            policy {
              system_requires_owner = true
            }
            """
        ])

        let governance = findings(of: session).filter { $0.category == .governance }
        #expect(
            governance.contains {
                $0.said.contains("system_requires_owner: this system states no owner")
            }
        )
    }

    // MARK: the summary is what check prints

    @Test func statesEverySystemTheWayTheUseCaseAnswersIt() async {
        let (session, useCases) = await aSession([
            "/work/threatmodel/broken.arch": "system \"Broken\" {",
            "/work/threatmodel/payments.arch": payments
        ])

        let expected = ["broken", "payments"].compactMap { name -> SystemCheck? in
            guard case .checked(let found) = useCases.checkSystem().execute(
                CheckSystemRequest(root: "/work", systemName: name)
            ) else { return nil }
            return found
        }

        #expect(session.checkedSystems == expected)
    }

    @Test func rereadsTheSummaryWhenAStaleAnswerIsDeleted() async throws {
        let (session, _) = await aSession([
            "/work/threatmodel/payments.arch": payments,
            "/work/threatmodel/payments.controls": """
            controls for "Payments" {
              stale threat "t-old" on component "gone" {
                control "Something a person answered" { status = "implemented" }
              }
            }

            """
        ])
        #expect(findings(of: session).contains { $0.category == .stale })

        let answer = try #require(session.staleAnswers.first)
        await session.removeStaleAnswer(answer)

        #expect(findings(of: session).contains { $0.category == .stale } == false)
    }

    /// Confirming "Delete all" removes every stale answer in one write, and
    /// `check` reports none of them.
    @Test func rereadsTheSummaryWhenEveryStaleAnswerIsDeletedAtOnce() async throws {
        let (session, _) = await aSession([
            "/work/threatmodel/payments.arch": payments,
            "/work/threatmodel/payments.controls": """
            controls for "Payments" {
              stale threat "t-old" on component "gone" {
                control "Something a person answered" { status = "implemented" }
              }
              stale threat "t-older" on component "also-gone" {
                control "Something else a person answered" { status = "implemented" }
              }
            }

            """
        ])
        #expect(findings(of: session).filter { $0.category == .stale }.count == 2)

        await session.removeStaleAnswers()

        #expect(session.staleAnswers.isEmpty)
        #expect(findings(of: session).contains { $0.category == .stale } == false)
    }

    // MARK: the sheet

    @Test func theSheetListsEveryLineCheckPrints() async {
        let (session, _) = await aSession([
            "/work/threatmodel/broken.arch": "system \"Broken\" {",
            "/work/threatmodel/payments.arch": payments
        ])

        let sheet = CheckSummarySheet(systems: session.checkedSystems, dismiss: {})

        let expected = session.checkedSystems.flatMap { system in
            system.findings.map(\.said)
                + [system.toleranceLine].compactMap(\.self)
                + (system.passes ? [system.allAnsweredLine] : [])
        }
        #expect(sheet.lines == expected)
    }

    @Test func theSheetSaysAPassingProjectPassesCheck() async {
        let (session, _) = await aSession([
            "/work/threatmodel/payments.arch": "system \"Payments\" { }\n"
        ])

        let sheet = CheckSummarySheet(systems: session.checkedSystems, dismiss: {})

        #expect(sheet.says == "This project passes check.")
        expectDrawn(sheet, "the check summary sheet with nothing to list")
    }

    @Test func drawsTheFindings() async {
        let (session, _) = await aSession([
            "/work/threatmodel/broken.arch": "system \"Broken\" {",
            "/work/threatmodel/payments.arch": payments
        ])

        let sheet = CheckSummarySheet(systems: session.checkedSystems, dismiss: {})

        #expect(sheet.says.hasPrefix("This project fails check:"))
        expectDrawn(sheet, "the check summary sheet")
    }

    private func expectDrawn(
        _ view: some View,
        width: Double = 640,
        height: Double = 480,
        _ what: String
    ) {
        guard let (image, _) = hostedDrawing(of: view, width: width, height: height) else {
            Issue.record("\(what) drew nothing at all")
            return
        }
        #expect(image.pixelsWide > 0, "\(what) drew the wrong width")
    }
}
