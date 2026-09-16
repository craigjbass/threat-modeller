import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// Writing one likelihood finding from the window.
///
/// Each use case reads the controls file, changes one `likelihood` block
/// and writes every other block back unchanged, so a person recording one
/// finding decides nothing about the rest.
@Suite("Writing a likelihood finding from the window")
struct WriteLikelihoodFindingTests {
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

            severity_override "medium" {
              rationale = "The credential is scoped to one read-only role."
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
        label: String = "no campaign has used this against our stack",
        tier: String? = "research",
        prior: Int? = nil,
        rationale: String = "No public reporting names this technique against this platform.",
        sources: [String] = ["https://example.com/threat-report"],
        threatId: String = "credential-theft",
        sourceKind: String = "component",
        sourceId: String = "api"
    ) -> WriteLikelihoodFindingResponse {
        app.writeLikelihoodFinding().execute(
            WriteLikelihoodFindingRequest(
                root: "/work",
                systemName: "payments",
                systemDisplayName: "Payments",
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId,
                label: label,
                tier: tier,
                prior: prior,
                rationale: rationale,
                sources: sources
            )
        )
    }

    private func writtenSource() throws -> ControlsSource {
        let written = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        return try #require(HclControlsSource().read(written).source)
    }

    // MARK: writing a finding

    @Test func writesTheFindingAndKeepsTheRest() throws {
        aProject(controls: answered)

        let response = write()

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let source = try writtenSource()
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(answer.likelihood?.label == "no campaign has used this against our stack")
        #expect(answer.likelihood?.likelihood == .research)
        #expect(
            answer.likelihood?.rationale
                == "No public reporting names this technique against this platform."
        )
        #expect(answer.likelihood?.sources == ["https://example.com/threat-report"])
        // The other blocks are not this finding, so they do not move.
        #expect(source.riskTolerance == "high")
        #expect(answer.severityDecision?.severityId == "medium")
        #expect(answer.controls.first?.status == .implemented)
    }

    @Test func writesAFindingAgainstAPrior() throws {
        aProject(controls: answered)

        let response = write(tier: nil, prior: 20)

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let source = try writtenSource()
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(answer.likelihood?.likelihood.id == "20")
        #expect(answer.likelihood?.likelihood.factor == 0.2)
    }

    /// The file is written by the one canonical writer, so writing what was
    /// read gives the same bytes back.
    @Test func roundTripsTheBytesThroughTheOneWriter() throws {
        aProject(controls: answered)

        _ = write()

        let written = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        let reread = try #require(HclControlsSource().read(written).source)
        #expect(HclControlsSource().write(reread) == written)
    }

    @Test func replacesTheFindingTheThreatHolds() throws {
        aProject(controls: answered)
        _ = write(tier: "commodity")

        let response = write(tier: "research")

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let source = try writtenSource()
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(answer.likelihood?.likelihood == .research)
    }

    @Test func writesIntoAThreatTheFileDoesNotAnswerYet() throws {
        aProject(controls: nil)

        let response = write()

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let source = try writtenSource()
        #expect(source.systemName == "Payments")
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(answer.likelihood?.likelihood == .research)
    }

    // MARK: what a write refuses

    @Test func refusesAFindingWithNoLabel() {
        aProject(controls: answered)

        let response = write(label: "  ")

        #expect(response == .refused(reason: "a likelihood finding needs to say what it found"))
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == answered)
    }

    @Test func refusesAFindingWithNoRationale() {
        aProject(controls: answered)

        let response = write(rationale: "  ")

        #expect(response == .refused(reason: "a likelihood finding needs a rationale"))
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == answered)
    }

    @Test func refusesAFindingThatStatesBothATierAndAPrior() {
        aProject(controls: answered)

        let response = write(tier: "research", prior: 20)

        #expect(response == .refused(reason: "a finding states a tier or a prior; it states one"))
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == answered)
    }

    @Test func refusesAFindingThatStatesNeither() {
        aProject(controls: answered)

        let response = write(tier: nil, prior: nil)

        #expect(response == .refused(reason: "a finding states a tier or a prior"))
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == answered)
    }

    @Test func refusesATierThisApplicationDoesNotHold() {
        aProject(controls: answered)

        let response = write(tier: "occasional")

        #expect(
            response
                == .refused(reason: "this application holds \"commodity\", \"targeted\" and \"research\"")
        )
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == answered)
    }

    @Test func refusesAPriorOutsideItsRange() {
        aProject(controls: answered)

        let response = write(tier: nil, prior: 101)

        #expect(response == .refused(reason: "a prior runs from 0 to 100"))
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == answered)
    }

    @Test func writesNoSystemTheProjectDoesNotHold() {
        aProject(controls: answered)

        let response = app.writeLikelihoodFinding().execute(
            WriteLikelihoodFindingRequest(
                root: "/work",
                systemName: "gone",
                systemDisplayName: nil,
                threatId: "credential-theft",
                sourceKind: "component",
                sourceId: "api",
                label: "no campaign has used this against our stack",
                tier: "research",
                rationale: "No public reporting names this technique against this platform."
            )
        )

        #expect(response == .noSuchSystem)
    }
}
