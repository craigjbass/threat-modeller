import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// Writing one threat's `impacts` list from the window.
///
/// The use case reads the controls file, changes one threat's `impacts`
/// list and writes every other block back unchanged, so a person stating
/// what one threat harms decides nothing about the rest.
@Suite("Writing a threat's impacts from the window")
struct WriteImpactsTests {
    private let app = TestDependencies()

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

            control "Enforce IMDSv2 to block SSRF-based credential theft" {
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
        _ impacts: [String],
        threatId: String = "credential-theft",
        sourceKind: String = "component",
        sourceId: String = "api"
    ) -> WriteImpactsResponse {
        app.writeImpacts().execute(
            WriteImpactsRequest(
                root: "/work",
                systemName: "payments",
                systemDisplayName: "Payments",
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId,
                impacts: impacts
            )
        )
    }

    private func writtenSource() throws -> ControlsSource {
        let written = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        return try #require(HclControlsSource().read(written).source)
    }

    // MARK: writing the list

    @Test func writesTheListAndKeepsTheRest() throws {
        aProject(controls: answered)

        let response = write(["integrity"])

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let source = try writtenSource()
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(answer.impacts == ["integrity"])
        // The other blocks are not this list, so they do not move.
        #expect(source.riskTolerance == "high")
        #expect(answer.likelihood?.label == "no campaign observed")
        #expect(answer.controls.first?.status == .implemented)
    }

    /// The file is written by the one canonical writer, so writing what was
    /// read gives the same bytes back.
    @Test func roundTripsTheBytesThroughTheOneWriter() throws {
        aProject(controls: answered)

        _ = write(["confidentiality", "integrity"])

        let written = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        let reread = try #require(HclControlsSource().read(written).source)
        #expect(HclControlsSource().write(reread) == written)
    }

    @Test func replacesTheListTheThreatHolds() throws {
        aProject(controls: answered)
        _ = write(["integrity"])

        let response = write(["availability", "confidentiality"])

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let source = try writtenSource()
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(answer.impacts == ["availability", "confidentiality"])
    }

    @Test func writesIntoAThreatTheFileDoesNotAnswerYet() throws {
        aProject(controls: nil)

        let response = write(["availability"])

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let source = try writtenSource()
        #expect(source.systemName == "Payments")
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(answer.impacts == ["availability"])
    }

    // MARK: what a write refuses

    @Test func refusesAnEmptyList() {
        aProject(controls: answered)

        let response = write([])

        #expect(response == .refused(reason: "a threat needs at least one impact"))
        let unchanged = app.project.text(at: "/work/threatmodel/payments.controls")
        #expect(unchanged == answered)
    }

    @Test func refusesAWordNotOnTheList() {
        aProject(controls: answered)

        let response = write(["worried"])

        #expect(response == .refused(
            reason: "this application holds \"confidentiality\", \"integrity\", \"availability\""
        ))
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == answered)
    }

    @Test func writesNoSystemTheProjectDoesNotHold() {
        aProject(controls: answered)

        let response = app.writeImpacts().execute(
            WriteImpactsRequest(
                root: "/work",
                systemName: "gone",
                systemDisplayName: nil,
                threatId: "credential-theft",
                sourceKind: "component",
                sourceId: "api",
                impacts: ["integrity"]
            )
        )

        #expect(response == .noSuchSystem)
    }

    // MARK: the filter reads the new impacts

    /// `ThreatFilter` reads `AssessedThreat.impacts`, the same field
    /// `AssessThreatModel` fills from `model.impactOverrides`. A read after
    /// the write proves the filter sees the chip's new state, not the
    /// STRIDE default it started from.
    @Test func theFilterReadsTheNewImpactsAfterTheWrite() throws {
        aProject(controls: answered)

        let architectureText = try #require(app.project.text(at: "/work/threatmodel/payments.arch"))
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: architectureText))
        _ = app.applyControlAnswers().execute(
            ApplyControlAnswersRequest(text: answered)
        )
        let before = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first {
                $0.threatId == "credential-theft"
            }
        )
        // No `impacts` attribute in `answered`. "credential-theft" carries
        // only the "spoofing" STRIDE category, which derives confidentiality
        // alone.
        #expect(before.impacts == ["confidentiality"])

        _ = write(["availability"])
        let controlsText = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: controlsText))

        let after = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first {
                $0.threatId == "credential-theft"
            }
        )
        #expect(after.impacts == ["availability"])
    }
}
