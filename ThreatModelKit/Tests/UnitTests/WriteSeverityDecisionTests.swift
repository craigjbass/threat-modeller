import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// Writing one severity decision from the window.
///
/// Each use case reads the controls file, changes one `severity_override`
/// block and writes every other block back unchanged, so a person deciding
/// one severity decides nothing about the rest.
@Suite("Writing a severity decision from the window")
struct WriteSeverityDecisionTests {
    private let app = TestDependencies()
    private let control = "Enforce IMDSv2 to block SSRF-based credential theft"

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private var answered: String {
        """
        controls for "Payments" {
          tolerance = "high"

          threat "credential-theft" on component "api" {
            severity = "critical"
            score    = 16

            likelihood "no campaign observed" {
              tier      = "research"
              rationale = "no known exploitation in the wild"
            }

            control "\(control)" {
              status = "implemented"
            }
          }
        }
        """
    }

    private func aProject(controls: String? = nil) {
        app.project.put(payments, at: "/work/threatmodel/payments.arch")
        if let controls {
            app.project.put(controls, at: "/work/threatmodel/payments.controls")
        }
    }

    private func write(
        _ decision: SeverityDecision,
        threatId: String = "credential-theft",
        sourceKind: String = "component",
        sourceId: String = "api"
    ) -> WriteSeverityDecisionResponse {
        app.writeSeverityDecision().execute(
            WriteSeverityDecisionRequest(
                root: "/work",
                systemName: "payments",
                systemDisplayName: "Payments",
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId,
                decision: decision
            )
        )
    }

    private func remove(
        threatId: String = "credential-theft",
        sourceKind: String = "component",
        sourceId: String = "api"
    ) -> RemoveSeverityDecisionResponse {
        app.removeSeverityDecision().execute(
            RemoveSeverityDecisionRequest(
                root: "/work",
                systemName: "payments",
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId
            )
        )
    }

    private func writtenSource() throws -> ControlsSource {
        let written = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        return try #require(HclControlsSource().read(written).source)
    }

    // MARK: writing a decision

    @Test func writesTheDecisionAndKeepsTheRest() throws {
        aProject(controls: answered)

        let response = write(
            SeverityDecision(
                severityId: "medium",
                rationale: "The credential is scoped to one read-only role.",
                sources: ["https://example.com/data-classification-policy"]
            )
        )

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let source = try writtenSource()
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(answer.severityDecision?.severityId == "medium")
        #expect(answer.severityDecision?.rationale == "The credential is scoped to one read-only role.")
        #expect(answer.severityDecision?.sources == ["https://example.com/data-classification-policy"])
        // The other blocks are not this decision, so they do not move.
        #expect(source.riskTolerance == "high")
        #expect(answer.likelihood?.label == "no campaign observed")
        #expect(answer.controls.first?.status == .implemented)
    }

    /// The file is written by the one canonical writer, so writing what was
    /// read gives the same bytes back.
    @Test func roundTripsTheBytesThroughTheOneWriter() throws {
        aProject(controls: answered)

        _ = write(SeverityDecision(severityId: "medium", rationale: "Scoped credential."))

        let written = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        let reread = try #require(HclControlsSource().read(written).source)
        #expect(HclControlsSource().write(reread) == written)
    }

    @Test func replacesTheDecisionTheThreatHolds() throws {
        aProject(controls: answered)
        _ = write(SeverityDecision(severityId: "medium", rationale: "Scoped credential."))

        let response = write(SeverityDecision(severityId: "low", rationale: "The role is read-only."))

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let source = try writtenSource()
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(answer.severityDecision?.severityId == "low")
        #expect(answer.severityDecision?.rationale == "The role is read-only.")
    }

    @Test func writesIntoAThreatTheFileDoesNotAnswerYet() throws {
        aProject(controls: nil)

        let response = write(SeverityDecision(severityId: "medium", rationale: "Scoped credential."))

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let source = try writtenSource()
        #expect(source.systemName == "Payments")
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(answer.severityDecision?.severityId == "medium")
    }

    // MARK: what a write refuses

    @Test func refusesADecisionWithNoRationale() {
        aProject(controls: answered)

        let response = write(SeverityDecision(severityId: "medium", rationale: "  "))

        #expect(response == .refused(reason: "a severity decision needs a rationale"))
        let unchanged = app.project.text(at: "/work/threatmodel/payments.controls")
        #expect(unchanged == answered)
    }

    @Test func refusesASeverityTheCatalogueDoesNotHold() {
        aProject(controls: answered)

        let response = write(SeverityDecision(severityId: "apocalyptic", rationale: "Everything ends."))

        #expect(response == .refused(
            reason: "\"apocalyptic\" is not a severity this catalogue holds"
        ))
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == answered)
    }

    @Test func writesNoSystemTheProjectDoesNotHold() {
        aProject(controls: answered)

        let response = app.writeSeverityDecision().execute(
            WriteSeverityDecisionRequest(
                root: "/work",
                systemName: "gone",
                systemDisplayName: nil,
                threatId: "credential-theft",
                sourceKind: "component",
                sourceId: "api",
                decision: SeverityDecision(severityId: "medium", rationale: "Scoped credential.")
            )
        )

        #expect(response == .noSuchSystem)
    }

    // MARK: removing a decision

    @Test func removesTheDecisionAndKeepsTheRest() throws {
        aProject(controls: answered)
        _ = write(SeverityDecision(severityId: "medium", rationale: "Scoped credential."))

        let response = remove()

        #expect(response == .removed(path: "/work/threatmodel/payments.controls"))
        let source = try writtenSource()
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(answer.severityDecision == nil)
        #expect(answer.likelihood?.label == "no campaign observed")
        #expect(answer.controls.first?.status == .implemented)
    }

    @Test func removesNothingWhenTheThreatHoldsNoDecision() {
        aProject(controls: answered)

        let response = remove()

        #expect(response == .noSuchDecision)
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == answered)
    }
}
