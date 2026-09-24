import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// Saving from the project window merges the on-screen control statuses into
/// the committed controls file. It must not drop what a person already wrote
/// there: a likelihood finding, a severity decision, or the file's tolerance.
@Suite("Saving a system's answers")
struct SaveSystemAnswersTests {
    private let app = TestDependencies()
    private let controlDescription = "Enforce IMDSv2 to block SSRF-based credential theft"

    private let architecture = """
    system "S" {
      risk_tolerance = "high"

      component "c1" { technology = "aws-ec2" data = "confidential" }
    }

    """

    private var committedControls: String {
        """
        controls for "S" {
          tolerance = "high"

          threat "credential-theft" on component "c1" {
            severity = "critical"
            score    = 16

            likelihood "no campaign observed" {
              tier      = "research"
              rationale = "no known exploitation in the wild"
            }

            severity_override "medium" {
              rationale = "the credential is scoped to one read-only role"
            }

            control "\(controlDescription)" {
              status = "not_implemented"
            }
          }
        }
        """
    }

    @Test func aSaveKeepsTheLikelihoodTheSeverityOverrideAndTheToleranceAcrossAStatusChange() throws {
        app.project.put(architecture, at: "/project/threatmodel/s.arch")
        app.project.put(committedControls, at: "/project/threatmodel/s.controls")

        _ = app.openSystem().execute(OpenSystemRequest(root: "/project", systemName: "s"))

        // The change a person makes on screen: one control ticked implemented.
        let assessed = app.assessThreatModel().execute(AssessThreatModelRequest())
        let threat = try #require(assessed.threats.first { $0.threatId == "credential-theft" })
        let control = try #require(threat.controls.first { $0.description == controlDescription })
        _ = app.recordControlImplemented().execute(
            RecordControlImplementedRequest(controlKey: control.key)
        )

        _ = app.saveSystemAnswers().execute(
            SaveSystemAnswersRequest(root: "/project", systemName: "s")
        )

        let written = try #require(app.project.text(at: "/project/threatmodel/s.controls"))
        let source = try #require(HclControlsSource().read(written).source)
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:c1")))

        #expect(source.riskTolerance == "high")
        #expect(answer.likelihood?.label == "no campaign observed")
        #expect(answer.severityDecision?.severityId == "medium")
        let savedControl = try #require(answer.controls.first { $0.description == controlDescription })
        #expect(savedControl.status == .implemented)
    }

    // MARK: the governance file the save writes

    private let governedArchitecture = """
    system "S" {
      component "c1" { technology = "aws-ec2" data = "confidential" }

      component "guard" { technology = "aws-waf" }

      mitigates guard -> c1 {
        status          = "proposed"

        recommendation "Turn the guard on" {
          text = "Turn the guard on in every region."
        }
      }
    }

    """

    private var governedControls: String {
        """
        controls for "S" {
          threat "credential-theft" on component "c1" {
            severity = "critical"
            score    = 16

            recommendation "Write the runbook" { }

            control "\(controlDescription)" {
              status = "accepted"
            }
          }
        }
        """
    }

    /// The executable writes the governance file after it writes the answers.
    /// The window saves the same answers, so it writes the same file: an
    /// accepted control, a recommendation and an action each take a stanza.
    @Test func aSaveWritesTheGovernanceFileTheCompileWrites() throws {
        app.project.put(governedArchitecture, at: "/project/threatmodel/s.arch")
        app.project.put(governedControls, at: "/project/threatmodel/s.controls")

        _ = app.openSystem().execute(OpenSystemRequest(root: "/project", systemName: "s"))
        _ = app.saveSystemAnswers().execute(
            SaveSystemAnswersRequest(root: "/project", systemName: "s")
        )

        let written = try #require(app.project.text(at: "/project/threatmodel/s.governance"))
        let source = try #require(HclGovernanceSource().read(written).source)
        let key = ThreatKey(threatId: "credential-theft", sourceId: "component:c1")
        let threat = try #require(source.threat(for: key))

        #expect(threat.accepted.contains { $0.control == controlDescription })
        #expect(threat.work.contains { $0.label == "Write the runbook" })
        #expect(source.actions.contains { $0.label == "Turn the guard on" })
    }

    /// A person writes an owner in the window, then saves the model. The save
    /// must keep the entry, because the compile keeps every stanza it finds.
    @Test func aSaveKeepsTheGovernanceEntryAPersonWrote() throws {
        app.project.put(governedArchitecture, at: "/project/threatmodel/s.arch")
        app.project.put(governedControls, at: "/project/threatmodel/s.controls")

        _ = app.openSystem().execute(OpenSystemRequest(root: "/project", systemName: "s"))
        _ = app.writeRiskAcceptance().execute(
            WriteRiskAcceptanceRequest(
                root: "/project",
                systemName: "s",
                threatId: "credential-theft",
                sourceKind: "component",
                sourceId: "c1",
                accepted: SourceAcceptedRisk(
                    control: controlDescription,
                    owner: "Head of Platform",
                    acceptedOn: "2026-01-05",
                    reviewBy: "2026-07-05",
                    rationale: "the credential is scoped to one read-only role"
                )
            )
        )

        _ = app.saveSystemAnswers().execute(
            SaveSystemAnswersRequest(root: "/project", systemName: "s")
        )

        let written = try #require(app.project.text(at: "/project/threatmodel/s.governance"))
        let source = try #require(HclGovernanceSource().read(written).source)
        let key = ThreatKey(threatId: "credential-theft", sourceId: "component:c1")
        let threat = try #require(source.threat(for: key))
        let accepted = try #require(threat.accepted.first { $0.control == controlDescription })

        #expect(accepted.owner == "Head of Platform")
        #expect(accepted.reviewBy == "2026-07-05")
    }

    // Issue #275: the export the save reads is the merged in-memory model,
    // so a split system whose mitigates edge crosses part files still writes
    // the action label the compile writes.
    @Test func aSaveWritesTheActionLabelOfASplitSystemWhoseMitigatesEdgeCrossesPartFiles() throws {
        app.project.put(
            """
            system "S" {
              component "c1" { technology = "aws-ec2" data = "confidential" }
            }

            """,
            at: "/project/threatmodel/s/arch/s.arch"
        )
        app.project.put(
            """
            component "guard" { technology = "aws-waf" }

            mitigates guard -> c1 {
              status = "proposed"

              recommendation "Turn the guard on" {
                text = "Turn the guard on in every region."
              }
            }
            """,
            at: "/project/threatmodel/s/arch/edge.arch"
        )
        app.project.put(governedControls, at: "/project/threatmodel/s/controls/s.controls")

        _ = app.openSystem().execute(OpenSystemRequest(root: "/project", systemName: "s"))
        _ = app.saveSystemAnswers().execute(
            SaveSystemAnswersRequest(root: "/project", systemName: "s")
        )

        let written = try #require(app.project.text(at: "/project/threatmodel/s/s.governance"))
        let source = try #require(HclGovernanceSource().read(written).source)
        #expect(source.actions.contains { $0.label == "Turn the guard on" })
    }

    /// A system that accepts nothing, recommends nothing and declares no
    /// action governs nothing. Nothing writes an empty file.
    @Test func aSaveWritesNoGovernanceFileForASystemThatGovernsNothing() throws {
        app.project.put(architecture, at: "/project/threatmodel/s.arch")
        app.project.put(committedControls, at: "/project/threatmodel/s.controls")

        _ = app.openSystem().execute(OpenSystemRequest(root: "/project", systemName: "s"))
        _ = app.saveSystemAnswers().execute(
            SaveSystemAnswersRequest(root: "/project", systemName: "s")
        )

        #expect(app.project.text(at: "/project/threatmodel/s.governance") == nil)
    }
}
