import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// Writing one threat's `recommendation` blocks from the window.
///
/// The use cases read the controls file, change one threat's recommendation
/// list and write every other block back unchanged, so a person saying what
/// to do about one threat says nothing about the rest.
@Suite("Writing a threat's recommendations from the window")
struct WriteRecommendationTests {
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

    @discardableResult
    private func write(
        _ text: String,
        replacing: String? = nil,
        note: String? = nil,
        sources: [String] = [],
        threatId: String = "credential-theft",
        sourceKind: String = "component",
        sourceId: String = "api"
    ) -> WriteRecommendationResponse {
        app.writeRecommendation().execute(
            WriteRecommendationRequest(
                root: "/work",
                systemName: "payments",
                systemDisplayName: "Payments",
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId,
                replacing: replacing,
                text: text,
                note: note,
                sources: sources
            )
        )
    }

    @discardableResult
    private func remove(_ text: String) -> RemoveRecommendationResponse {
        app.removeRecommendation().execute(
            RemoveRecommendationRequest(
                root: "/work",
                systemName: "payments",
                threatId: "credential-theft",
                sourceKind: "component",
                sourceId: "api",
                text: text
            )
        )
    }

    private func writtenSource() throws -> ControlsSource {
        let written = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        return try #require(HclControlsSource().read(written).source)
    }

    private func writtenAnswer() throws -> SourceThreatAnswer {
        try #require(try writtenSource().answer(for: ThreatKey("credential-theft@component:api")))
    }

    // MARK: writing a block

    @Test func writesTheBlockAndKeepsTheRest() throws {
        aProject(controls: answered)

        let response = write(
            "Enforce IMDSv2 on every instance",
            note: "The launch template sets it.",
            sources: ["https://example.test/imds"]
        )

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let answer = try writtenAnswer()
        #expect(answer.recommendations.count == 1)
        #expect(answer.recommendations.first?.text == "Enforce IMDSv2 on every instance")
        #expect(answer.recommendations.first?.note == "The launch template sets it.")
        #expect(answer.recommendations.first?.sources == ["https://example.test/imds"])
        // The other blocks are not this list, so they do not move.
        let source = try writtenSource()
        #expect(source.riskTolerance == "high")
        #expect(answer.likelihood?.label == "no campaign observed")
        #expect(answer.controls.first?.status == .implemented)
        #expect(answer.severityLabel == "critical")
    }

    @Test func writesASecondBlockBesideTheFirst() throws {
        aProject(controls: answered)
        write("Enforce IMDSv2 on every instance")

        let response = write("Rotate the instance role every 90 days")

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let answer = try writtenAnswer()
        #expect(
            answer.recommendations.map(\.text)
                == ["Enforce IMDSv2 on every instance", "Rotate the instance role every 90 days"]
        )
    }

    @Test func writesIntoAThreatTheFileDoesNotAnswerYet() throws {
        aProject(controls: nil)

        let response = write("Enforce IMDSv2 on every instance")

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let source = try writtenSource()
        #expect(source.systemName == "Payments")
        let answer = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(answer.recommendations.map(\.text) == ["Enforce IMDSv2 on every instance"])
    }

    /// The file is written by the one canonical writer, so writing what was
    /// read gives the same bytes back.
    @Test func roundTripsTheBytesThroughTheOneWriter() throws {
        aProject(controls: answered)

        write(
            "Enforce IMDSv2 on every instance",
            note: "The launch template sets it.",
            sources: ["https://example.test/imds"]
        )

        let written = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        let reread = try #require(HclControlsSource().read(written).source)
        #expect(HclControlsSource().write(reread) == written)
    }

    /// A block a person writes in the window and the same block typed into
    /// the file by hand are the same bytes, because one writer writes both.
    @Test func theWindowAndTheHandWriteTheSameBytes() throws {
        aProject(controls: answered)
        write(
            "Enforce IMDSv2 on every instance",
            note: "The launch template sets it.",
            sources: ["https://example.test/imds"]
        )
        let fromTheWindow = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))

        let byHand = """
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

            recommendation "Enforce IMDSv2 on every instance" {
              note    = "The launch template sets it."
              sources = ["https://example.test/imds"]
            }
          }
        }
        """
        let read = try #require(HclControlsSource().read(byHand).source)
        #expect(HclControlsSource().write(read) == fromTheWindow)
    }

    // MARK: editing a block

    @Test func replacesTheBlockTheTextNames() throws {
        aProject(controls: answered)
        write("Enforce IMDSv2 on every instance", note: "The launch template sets it.")
        write("Rotate the instance role every 90 days")

        let response = write(
            "Enforce IMDSv2 on every hosted instance",
            replacing: "Enforce IMDSv2 on every instance",
            note: "The launch template sets it."
        )

        #expect(response == .written(path: "/work/threatmodel/payments.controls"))
        let answer = try writtenAnswer()
        #expect(
            answer.recommendations.map(\.text)
                == [
                    "Enforce IMDSv2 on every hosted instance",
                    "Rotate the instance role every 90 days"
                ]
        )
    }

    /// An edit that keeps the text and changes the note is not a clash with
    /// itself.
    @Test func changesTheNoteOfTheBlockItReplaces() throws {
        aProject(controls: answered)
        write("Enforce IMDSv2 on every instance", note: "The launch template sets it.")

        write(
            "Enforce IMDSv2 on every instance",
            replacing: "Enforce IMDSv2 on every instance",
            note: "Terraform sets it."
        )

        let answer = try writtenAnswer()
        #expect(answer.recommendations.count == 1)
        #expect(answer.recommendations.first?.note == "Terraform sets it.")
    }

    // MARK: removing a block

    @Test func removesTheBlockTheTextNames() throws {
        aProject(controls: answered)
        write("Enforce IMDSv2 on every instance")
        write("Rotate the instance role every 90 days")

        let response = remove("Enforce IMDSv2 on every instance")

        #expect(response == .removed(path: "/work/threatmodel/payments.controls"))
        let answer = try writtenAnswer()
        #expect(answer.recommendations.map(\.text) == ["Rotate the instance role every 90 days"])
        // The rest of the block stays.
        #expect(answer.controls.first?.status == .implemented)
    }

    @Test func removesNoBlockTheThreatDoesNotHold() {
        aProject(controls: answered)

        let response = remove("Enforce IMDSv2 on every instance")

        #expect(response == .noSuchRecommendation)
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == answered)
    }

    // MARK: what a write refuses

    @Test func refusesABlockWithNoText() {
        aProject(controls: answered)

        let response = write("   ")

        #expect(response == .refused(reason: "a recommendation needs text"))
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == answered)
    }

    @Test func refusesASecondBlockSayingTheSameText() throws {
        aProject(controls: answered)
        write("Enforce IMDSv2 on every instance")
        let after = app.project.text(at: "/work/threatmodel/payments.controls")

        let response = write("Enforce IMDSv2 on every instance")

        #expect(
            response == .refused(reason: "this threat already says \"Enforce IMDSv2 on every instance\"")
        )
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == after)
    }

    @Test func refusesAnEditOfABlockTheThreatNoLongerHolds() {
        aProject(controls: answered)

        let response = write("Rotate the role", replacing: "Enforce IMDSv2 on every instance")

        #expect(
            response == .refused(reason: "this threat no longer says \"Enforce IMDSv2 on every instance\"")
        )
        #expect(app.project.text(at: "/work/threatmodel/payments.controls") == answered)
    }

    @Test func writesNoSystemTheProjectDoesNotHold() {
        aProject(controls: answered)

        let response = app.writeRecommendation().execute(
            WriteRecommendationRequest(
                root: "/work",
                systemName: "gone",
                threatId: "credential-theft",
                sourceKind: "component",
                sourceId: "api",
                text: "Enforce IMDSv2 on every instance"
            )
        )

        #expect(response == .noSuchSystem)
    }

    // MARK: what the card and the report read after the write

    /// `AssessThreatModel` fills `AssessedThreat.recommendations` from
    /// `model.recommendations`, the map `ApplyControlAnswers` reads out of
    /// the controls file. A read after the write proves the card shows the
    /// block a person just wrote.
    @Test func theThreatCardReadsTheBlockAfterTheWrite() throws {
        aProject(controls: answered)
        let architectureText = try #require(app.project.text(at: "/work/threatmodel/payments.arch"))
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: architectureText))

        write("Enforce IMDSv2 on every instance", note: "The launch template sets it.")

        let controlsText = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: controlsText))
        let threat = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first {
                $0.threatId == "credential-theft"
            }
        )
        #expect(threat.recommendations.map(\.text) == ["Enforce IMDSv2 on every instance"])
        #expect(threat.recommendations.first?.note == "The launch template sets it.")
    }

    @Test func theReportListsTheRecommendationAfterTheWrite() throws {
        aProject(controls: answered)
        let architectureText = try #require(app.project.text(at: "/work/threatmodel/payments.arch"))
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: architectureText))

        write("Enforce IMDSv2 on every instance", note: "The launch template sets it.")

        let controlsText = try #require(app.project.text(at: "/work/threatmodel/payments.controls"))
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: controlsText))
        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
        #expect(report.recommendations.map(\.text) == ["Enforce IMDSv2 on every instance"])

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
        #expect(markdown.contains("## Recommendations"))
        #expect(markdown.contains("- Enforce IMDSv2 on every instance"))
        #expect(markdown.contains("  - The launch template sets it."))
    }
}
