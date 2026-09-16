import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// Writing what proves a control is in place, from the window: the tier, the
/// reference and the verified-on date land on the model, the assessment shows
/// them, and a project save writes them into the controls file.
@Suite("Writing evidence on a control")
struct SetControlEvidenceTests {
    private let app = TestDependencies()

    private func aControl() throws -> AssessedControl {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "confidential")
        )
        let assessed = app.assessThreatModel().execute(AssessThreatModelRequest())
        let threat = try #require(assessed.threats.first { $0.threatId == "credential-theft" })
        return try #require(threat.controls.first)
    }

    private func theControl() throws -> AssessedControl {
        let assessed = app.assessThreatModel().execute(AssessThreatModelRequest())
        let threat = try #require(assessed.threats.first { $0.threatId == "credential-theft" })
        return try #require(threat.controls.first)
    }

    @Test func recordsTheTierTheReferenceAndTheDate() throws {
        let control = try aControl()

        let response = app.setControlEvidence().execute(
            SetControlEvidenceRequest(
                controlKey: control.key,
                evidenceId: "tested",
                reference: "ci/imdsv2-test",
                verifiedOn: "2026-09-01"
            )
        )

        #expect(response == .recorded)
        let shown = try theControl()
        #expect(shown.evidenceId == "tested")
        #expect(shown.evidenceReference == "ci/imdsv2-test")
        #expect(shown.verifiedOn == "2026-09-01")
    }

    @Test func refusesATierThisApplicationDoesNotHold() throws {
        let control = try aControl()

        let response = app.setControlEvidence().execute(
            SetControlEvidenceRequest(
                controlKey: control.key,
                evidenceId: "believed",
                reference: "",
                verifiedOn: nil
            )
        )

        #expect(response == .unknownEvidence)
        var message: String?
        response.describe(into: &message)
        #expect(message != nil)
    }

    @Test func refusesATextThatIsNotADate() throws {
        let control = try aControl()

        let response = app.setControlEvidence().execute(
            SetControlEvidenceRequest(
                controlKey: control.key,
                evidenceId: "tested",
                reference: "",
                verifiedOn: "soon"
            )
        )

        #expect(response == .notADate("verified_on is \"soon\"; a date is written YYYY-MM-DD"))
    }

    @Test func clearsTheProofWhenEverythingIsEmpty() throws {
        let control = try aControl()
        _ = app.setControlEvidence().execute(
            SetControlEvidenceRequest(
                controlKey: control.key,
                evidenceId: "asserted",
                reference: "",
                verifiedOn: nil
            )
        )

        let response = app.setControlEvidence().execute(
            SetControlEvidenceRequest(
                controlKey: control.key,
                evidenceId: nil,
                reference: "",
                verifiedOn: nil
            )
        )

        #expect(response == .recorded)
        let shown = try theControl()
        #expect(shown.evidenceId == nil)
        #expect(shown.verifiedOn == nil)
    }

    @Test func namesItsChange() throws {
        let control = try aControl()

        _ = app.setControlEvidence().execute(
            SetControlEvidenceRequest(
                controlKey: control.key,
                evidenceId: "audited",
                reference: "",
                verifiedOn: nil
            )
        )

        #expect(app.modelStore.undoLabel == ChangeLabel.setControlEvidence)
    }
}

/// A compensating control states the same three attributes.
@Suite("Evidence on a compensating control")
struct CompensatingEvidenceTests {
    private let app = TestDependencies()

    private func aThreat() throws -> AssessedThreat {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "confidential")
        )
        let assessed = app.assessThreatModel().execute(AssessThreatModelRequest())
        return try #require(assessed.threats.first { $0.threatId == "credential-theft" })
    }

    @Test func recordsWhatProvesTheCompensatingControl() throws {
        let threat = try aThreat()

        let response = app.setCompensatingControl().execute(
            SetCompensatingControlRequest(
                threatKey: threat.threatKey,
                label: "Watched by the SIEM",
                reducesRiskBy: 50,
                rationale: "The account alerts on use.",
                evidenceId: "configured",
                evidenceReference: "splunk/saved-search/admin-login",
                verifiedOn: "2026-08-30"
            )
        )

        #expect(response == .recorded)
        let assessed = app.assessThreatModel().execute(AssessThreatModelRequest())
        let shown = try #require(assessed.threats.first { $0.threatId == "credential-theft" })
        #expect(shown.compensatingEvidenceId == "configured")
        #expect(shown.compensatingEvidenceReference == "splunk/saved-search/admin-login")
        #expect(shown.compensatingVerifiedOn == "2026-08-30")
    }

    @Test func refusesATierThisApplicationDoesNotHold() throws {
        let threat = try aThreat()

        let response = app.setCompensatingControl().execute(
            SetCompensatingControlRequest(
                threatKey: threat.threatKey,
                label: "Watched by the SIEM",
                reducesRiskBy: 50,
                rationale: "The account alerts on use.",
                evidenceId: "believed"
            )
        )

        #expect(response == .unknownEvidence)
    }

    @Test func refusesATextThatIsNotADate() throws {
        let threat = try aThreat()

        let response = app.setCompensatingControl().execute(
            SetCompensatingControlRequest(
                threatKey: threat.threatKey,
                label: "Watched by the SIEM",
                reducesRiskBy: 50,
                rationale: "The account alerts on use.",
                verifiedOn: "soon"
            )
        )

        #expect(response == .notADate("verified_on is \"soon\"; a date is written YYYY-MM-DD"))
    }
}

/// A project save carries the evidence into the controls file, a reopen reads
/// it back, and the check failure it answers clears.
@Suite("Saving evidence into the controls file")
struct SaveControlEvidenceTests {
    private let app = TestDependencies()
    private let controlDescription = "Enforce IMDSv2 to block SSRF-based credential theft"
    private let controlsPath = "/project/threatmodel/s.controls"

    private let architecture = """
    system "S" {
      requires_evidence_above = "low"

      component "c1" { technology = "aws-ec2" data = "confidential" }
    }

    """

    private var committedControls: String {
        """
        controls for "S" {
          threat "credential-theft" on component "c1" {
            control "\(controlDescription)" {
              status = "implemented"
            }
          }
        }
        """
    }

    private func openTheProject() {
        app.project.put(architecture, at: "/project/threatmodel/s.arch")
        app.project.put(committedControls, at: controlsPath)
        _ = app.openSystem().execute(OpenSystemRequest(root: "/project", systemName: "s"))
    }

    private func theControl() throws -> AssessedControl {
        let assessed = app.assessThreatModel().execute(AssessThreatModelRequest())
        let threat = try #require(assessed.threats.first { $0.threatId == "credential-theft" })
        return try #require(threat.controls.first { $0.description == controlDescription })
    }

    private func save() {
        _ = app.saveSystemAnswers().execute(
            SaveSystemAnswersRequest(root: "/project", systemName: "s")
        )
    }

    private func writtenAnswer() throws -> SourceThreatAnswer {
        let written = try #require(app.project.text(at: controlsPath))
        let source = try #require(HclControlsSource().read(written).source)
        return try #require(source.answer(for: ThreatKey("credential-theft@component:c1")))
    }

    @Test func aSaveWritesTheEvidenceTheWindowStates() throws {
        openTheProject()
        let control = try theControl()

        _ = app.setControlEvidence().execute(
            SetControlEvidenceRequest(
                controlKey: control.key,
                evidenceId: "tested",
                reference: "ci/imdsv2-test",
                verifiedOn: "2026-09-01"
            )
        )
        save()

        let answer = try writtenAnswer()
        let saved = try #require(answer.controls.first { $0.description == controlDescription })
        #expect(saved.proof.evidence == .tested)
        #expect(saved.proof.reference == "ci/imdsv2-test")
        #expect(saved.proof.verifiedOn?.description == "2026-09-01")
    }

    @Test func theOneWriterRoundTripsTheBytes() throws {
        openTheProject()
        let control = try theControl()

        _ = app.setControlEvidence().execute(
            SetControlEvidenceRequest(
                controlKey: control.key,
                evidenceId: "tested",
                reference: "ci/imdsv2-test",
                verifiedOn: "2026-09-01"
            )
        )
        save()

        let written = try #require(app.project.text(at: controlsPath))
        let gateway = HclControlsSource()
        let source = try #require(gateway.read(written).source)
        #expect(gateway.write(source) == written)
    }

    @Test func aSaveKeepsTheEvidenceTheFileStatesAcrossAStatusChange() throws {
        app.project.put(architecture, at: "/project/threatmodel/s.arch")
        app.project.put(
            """
            controls for "S" {
              threat "credential-theft" on component "c1" {
                control "\(controlDescription)" {
                  status      = "implemented"
                  evidence    = "audited"
                  reference   = "soc2/2026"
                  verified_on = "2026-07-15"
                }
              }
            }
            """,
            at: controlsPath
        )
        _ = app.openSystem().execute(OpenSystemRequest(root: "/project", systemName: "s"))

        let assessed = app.assessThreatModel().execute(AssessThreatModelRequest())
        let threat = try #require(assessed.threats.first { $0.threatId == "credential-theft" })
        let other = try #require(threat.controls.first { $0.description != controlDescription })
        _ = app.setControlStatus().execute(
            SetControlStatusRequest(controlKey: other.key, statusId: "not_applicable")
        )
        save()

        let answer = try writtenAnswer()
        let saved = try #require(answer.controls.first { $0.description == controlDescription })
        #expect(saved.proof.evidence == .audited)
        #expect(saved.proof.reference == "soc2/2026")
        #expect(saved.proof.verifiedOn?.description == "2026-07-15")
    }

    @Test func aSaveWritesTheCompensatingEvidence() throws {
        openTheProject()
        let assessed = app.assessThreatModel().execute(AssessThreatModelRequest())
        let threat = try #require(assessed.threats.first { $0.threatId == "credential-theft" })

        _ = app.setCompensatingControl().execute(
            SetCompensatingControlRequest(
                threatKey: threat.threatKey,
                label: "Watched by the SIEM",
                reducesRiskBy: 50,
                rationale: "The account alerts on use.",
                evidenceId: "configured",
                evidenceReference: "splunk/saved-search/admin-login",
                verifiedOn: "2026-08-30"
            )
        )
        save()

        let answer = try writtenAnswer()
        let compensating = try #require(answer.compensating.first)
        #expect(compensating.proof.evidence == .configured)
        #expect(compensating.proof.reference == "splunk/saved-search/admin-login")
        #expect(compensating.proof.verifiedOn?.description == "2026-08-30")
    }

    @Test func aReopenShowsTheEvidence() throws {
        openTheProject()
        let control = try theControl()

        _ = app.setControlEvidence().execute(
            SetControlEvidenceRequest(
                controlKey: control.key,
                evidenceId: "documented",
                reference: "runbook/imdsv2",
                verifiedOn: nil
            )
        )
        save()
        _ = app.openSystem().execute(OpenSystemRequest(root: "/project", systemName: "s"))

        let reopened = try theControl()
        #expect(reopened.evidenceId == "documented")
        #expect(reopened.evidenceReference == "runbook/imdsv2")
    }

    @Test func theCheckFailureClearsWhenATierIsWritten() throws {
        openTheProject()

        func unevidencedFindings() throws -> [String] {
            let response = app.checkSystem().execute(
                CheckSystemRequest(root: "/project", systemName: "s", tolerance: nil)
            )
            guard case .checked(let check) = response else {
                Issue.record("expected a check")
                return []
            }
            return check.governance.filter { $0.contains("no evidence") }
        }

        #expect(try unevidencedFindings().isEmpty == false)

        let control = try theControl()
        _ = app.setControlEvidence().execute(
            SetControlEvidenceRequest(
                controlKey: control.key,
                evidenceId: "tested",
                reference: "ci/imdsv2-test",
                verifiedOn: "2026-09-01"
            )
        )
        save()

        #expect(try unevidencedFindings().isEmpty)
    }
}
