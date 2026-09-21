import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Writing a governance entry in the window, end to end: the file the use
/// case writes, the card that states it, the check failure it clears, and the
/// planned-work list.
@MainActor
@Suite("Writing a governance entry in the window")
struct GovernanceEditorFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private let accepting = """
    controls for "Payments" {
      threat "credential-theft" on component "api" {
        control "Enforce IMDSv2 to block SSRF-based credential theft" {
          status = "accepted"
        }
      }
    }

    """

    private let control = "Enforce IMDSv2 to block SSRF-based credential theft"

    /// A system whose assumed mitigates edge carries an action. The
    /// governance file governs the action's label.
    private let paymentsWithAnAction = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "guard" { technology = "aws-waf" }

      mitigates guard -> api {
        status          = "proposed"

        recommendation "Turn the guard on" {
          text = "Turn the guard on in every region."
        }
      }
    }

    """

    /// Answers that accept one control and recommend one piece of work.
    private let recommending = """
    controls for "Payments" {
      threat "credential-theft" on component "api" {
        recommendation "Write the runbook" { }

        control "Enforce IMDSv2 to block SSRF-based credential theft" {
          status = "accepted"
        }
      }
    }

    """

    private func aProject(files: [String: String] = [:]) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.project.put(accepting, at: "/work/threatmodel/payments.controls")
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

    private func governanceFindings(of session: ProjectSession) -> [String] {
        session.checkedSystems
            .flatMap(\.findings)
            .filter { $0.category == .governance }
            .map(\.said)
    }

    // MARK: an accepted risk

    @Test func writesTheAcceptanceAndTheCardStatesIt() async throws {
        let (session, useCases) = await aProject()

        await session.writeRiskAcceptance(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            accepted: SourceAcceptedRisk(
                control: control,
                owner: "Head of Platform",
                acceptedOn: "2026-09-01",
                reviewBy: "2027-03-01",
                rationale: "The MFA rollout waits on the SSO migration.",
                sources: ["https://example.com/RSK-412"]
            )
        )

        let written = try #require(
            useCases.project.text(at: "/work/threatmodel/payments.governance")
        )
        #expect(written.contains("governance for \"Payments\" {"))
        #expect(written.contains("owner       = \"Head of Platform\""))
        #expect(session.errorMessage == nil)

        // The project read the files again, so the card states the owner.
        let model = try #require(session.model)
        let threat = try #require(
            model.threats.first {
                $0.threatId == "credential-theft" && $0.source.id == "component:api"
            }
        )
        let governed = try #require(threat.controls.first { $0.description == control })
        #expect(governed.acceptedBy == "Head of Platform")
        #expect(governed.reviewBy == "2027-03-01")

        // The editor reads the file back, sources and rationale included.
        let source = try #require(session.governanceSource)
        let stanza = try #require(source.threats.first?.accepted.first)
        #expect(stanza.rationale == "The MFA rollout waits on the SSO migration.")
        #expect(stanza.sources == ["https://example.com/RSK-412"])
    }

    @Test func aWrittenEntryClearsTheCheckFailure() async {
        let (session, _) = await aProject()
        #expect(
            governanceFindings(of: session).contains {
                $0.contains(
                    "credential-theft@component:api is accepted and has no governance entry"
                )
            }
        )

        await session.writeRiskAcceptance(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            accepted: SourceAcceptedRisk(
                control: control,
                owner: "Head of Platform",
                reviewBy: "2027-03-01"
            )
        )

        #expect(
            governanceFindings(of: session).contains {
                $0.contains("credential-theft@component:api")
            } == false
        )
    }

    // MARK: planned work

    /// The executable writes a work stanza for every recommendation and every
    /// action when it compiles. The window saves the same answers, so the
    /// list holds them without a run of the executable.
    @Test func aSaveWritesTheWorkStanzasTheListShows() async throws {
        let (session, useCases) = await aProject(files: [
            "/work/threatmodel/payments.arch": paymentsWithAnAction,
            "/work/threatmodel/payments.controls": recommending
        ])
        #expect(session.plannedWork.isEmpty)

        await session.save()

        #expect(useCases.project.text(at: "/work/threatmodel/payments.governance") != nil)
        #expect(session.plannedWork.contains { $0.work.label == "Write the runbook" })
        #expect(session.plannedWork.contains { $0.work.label == "Turn the guard on" })
    }


    @Test func listsAddsAndChangesAPlannedWorkItem() async throws {
        let (session, _) = await aProject(files: [
            "/work/threatmodel/payments.governance": """
            governance for "Payments" {
              threat "credential-theft" on component "api" {
                work "Protect the plist" {
                  owner = "Platform team"
                }
              }

              action "reenable-devtool-rules" {
              }
            }

            """
        ])

        // Listed: the work stanza and the action, in file order.
        #expect(session.plannedWork.map(\.work.label)
            == ["Protect the plist", "reenable-devtool-rules"])

        // Added: a label the file does not hold appends a stanza.
        await session.writePlannedWork(
            place: .threat(threatId: "credential-theft", sourceKind: "component", sourceId: "api"),
            work: SourcePlannedWork(label: "Rotate the keys", owner: "Platform team")
        )
        #expect(session.plannedWork.map(\.work.label)
            == ["Protect the plist", "Rotate the keys", "reenable-devtool-rules"])

        // Changed: the same label replaces the stanza.
        await session.writePlannedWork(
            place: .action,
            work: SourcePlannedWork(
                label: "reenable-devtool-rules",
                owner: "Endpoint team",
                effort: "small",
                dueBy: "2026-10-15",
                status: "in_progress",
                acceptance: "The read rules are on."
            )
        )
        let action = try #require(
            session.plannedWork.first { $0.work.label == "reenable-devtool-rules" }
        )
        #expect(action.work.owner == "Endpoint team")
        #expect(action.work.status == "in_progress")
        #expect(session.plannedWork.count == 3)
        #expect(session.errorMessage == nil)
    }

    // MARK: one writer states the canonical shape

    @Test func theWindowAndAHandWrittenFileAreTheSameBytes() async throws {
        let (session, useCases) = await aProject()

        await session.writeRiskAcceptance(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            accepted: SourceAcceptedRisk(
                control: control,
                owner: "Head of Platform",
                acceptedOn: "2026-09-01",
                reviewBy: "2027-03-01",
                rationale: "The MFA rollout waits on the SSO migration.",
                sources: ["https://example.com/RSK-412"]
            )
        )
        await session.writePlannedWork(
            place: .action,
            work: SourcePlannedWork(label: "reenable-devtool-rules", owner: "Endpoint team")
        )

        let written = try #require(
            useCases.project.text(at: "/work/threatmodel/payments.governance")
        )

        // A person writing the same decisions by hand, through the one writer,
        // writes the same bytes.
        let byHand = HclGovernanceSource().write(
            GovernanceSource(
                systemName: "Payments",
                threats: [
                    SourceGovernedThreat(
                        threatId: "credential-theft",
                        sourceKind: "component",
                        sourceId: "api",
                        accepted: [
                            SourceAcceptedRisk(
                                control: control,
                                owner: "Head of Platform",
                                acceptedOn: "2026-09-01",
                                reviewBy: "2027-03-01",
                                rationale: "The MFA rollout waits on the SSO migration.",
                                sources: ["https://example.com/RSK-412"]
                            )
                        ]
                    )
                ],
                actions: [
                    SourcePlannedWork(label: "reenable-devtool-rules", owner: "Endpoint team")
                ]
            )
        )
        #expect(written == byHand)
    }

    // MARK: the sheets

    @Test func drawsTheGovernanceSheet() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let threat = try #require(
            model.threats.first {
                $0.threatId == "credential-theft" && $0.source.id == "component:api"
            }
        )
        let accepted = try #require(threat.controls.first { $0.description == control })

        let sheet = GovernanceSheet(threat: threat, control: accepted, project: session)

        expectDrawn(sheet, "the governance sheet")
    }

    @Test func drawsThePlannedWorkSheet() async throws {
        let (session, _) = await aProject(files: [
            "/work/threatmodel/payments.governance": """
            governance for "Payments" {
              action "reenable-devtool-rules" {
                owner = "Endpoint team"
              }
            }

            """
        ])
        let model = try #require(session.model)

        let sheet = PlannedWorkSheet(project: session, threats: model.threats, dismiss: {})

        expectDrawn(sheet, width: 760, height: 520, "the planned work sheet")
    }

    /// The place one of the assessment's threat keys names, for the sheet
    /// that writes governance: `connection` in a key is `flow` in the file.
    @Test func aThreatKeyNamesTheGovernedPlace() {
        #expect(
            GovernanceSheet.place(of: "credential-theft@component:api")
                == PlannedWorkPlace.threat(
                    threatId: "credential-theft",
                    sourceKind: "component",
                    sourceId: "api"
                )
        )
        #expect(
            GovernanceSheet.place(of: "connection-mitm@connection:api->db")
                == PlannedWorkPlace.threat(
                    threatId: "connection-mitm",
                    sourceKind: "flow",
                    sourceId: "api->db"
                )
        )
    }

    private func expectDrawn(
        _ view: some View,
        width: Double = 520,
        height: Double = 560,
        _ what: String
    ) {
        guard let (image, _) = hostedDrawing(of: view, width: width, height: height) else {
            Issue.record("\(what) drew nothing at all")
            return
        }
        #expect(image.pixelsWide > 0, "\(what) drew the wrong width")
    }
}
