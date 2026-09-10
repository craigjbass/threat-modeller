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
}
