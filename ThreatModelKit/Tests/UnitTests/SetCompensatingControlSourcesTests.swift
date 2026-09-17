import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// A save of a compensating control keeps the `sources` the file already
/// states, the way it keeps the rationale and the evidence.
///
/// Issue #168: `SetCompensatingControl` built the compensating control with
/// no `sources`, so any save dropped what the file held.
@Suite("Saving a compensating control keeps its sources")
struct SetCompensatingControlSourcesTests {
    private let app = TestDependencies()
    private let controlsPath = "/project/threatmodel/s.controls"

    private let architecture = """
    system "S" {
      component "c1" { technology = "aws-ec2" data = "confidential" }
    }

    """

    private var committedControls: String {
        """
        controls for "S" {
          threat "credential-theft" on component "c1" {
            compensating "Watched by the SIEM" {
              reduces_risk_by = 50
              rationale       = "The account alerts on use."
              sources         = ["https://example.com/break-glass-runbook"]
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

    @Test func anUnrelatedEditKeepsTheSourcesAndTheBytesRoundTrip() throws {
        openTheProject()

        // An edit to the percentage, the way the sheet sends the whole
        // record on every save. The sources on screen come from the file,
        // the same way the rationale does.
        _ = app.setCompensatingControl().execute(
            SetCompensatingControlRequest(
                threatKey: "credential-theft@component:c1",
                label: "Watched by the SIEM",
                reducesRiskBy: 60,
                rationale: "The account alerts on use.",
                sources: ["https://example.com/break-glass-runbook"]
            )
        )
        save()

        let answer = try writtenAnswer()
        let compensating = try #require(answer.compensating.first)
        #expect(compensating.sources == ["https://example.com/break-glass-runbook"])

        let written = try #require(app.project.text(at: controlsPath))
        let gateway = HclControlsSource()
        let source = try #require(gateway.read(written).source)
        #expect(gateway.write(source) == written)
    }
}
