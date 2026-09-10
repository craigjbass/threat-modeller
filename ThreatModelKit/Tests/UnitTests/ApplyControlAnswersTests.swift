import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

@Suite("Applying and checking the answers a file holds")
struct ApplyControlAnswersTests {
    private let app = TestDependencies()
    private let controls = HclControlsSource()

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func compiled(_ existing: String? = nil) -> String {
        guard case .compiled(let text, _, _, _) = app.compileControls().execute(
            CompileControlsRequest(architectureText: payments, controlsText: existing)
        ) else {
            Issue.record("the controls did not compile")
            return ""
        }
        return text
    }

    private func drawTheModel() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
    }

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    /// Answers the first control of the first threat, and compensates it.
    private func answered(_ text: String, compensate: Bool = false) throws -> String {
        let source = try #require(controls.read(text).source)
        let first = source.answers[0]
        let answered = SourceThreatAnswer(
            threatId: first.threatId,
            sourceKind: first.sourceKind,
            sourceId: first.sourceId,
            severityLabel: first.severityLabel,
            score: first.score,
            controls: [
                SourceControlAnswer(
                    description: first.controls[0].description,
                    status: .implemented,
                    note: "Okta"
                )
            ] + first.controls.dropFirst(),
            compensating: compensate
                ? [CompensatingControl(label: "SIEM", reducesRiskBy: 50, rationale: "It alerts.")]
                : []
        )
        return controls.write(
            ControlsSource(
                systemName: source.systemName,
                catalogueTag: source.catalogueTag,
                answers: [answered] + source.answers.dropFirst()
            )
        )
    }

    @Test func recordsTheControlsTheFileAnswers() throws {
        drawTheModel()
        let text = try answered(compiled())

        let response = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        guard case .applied(let answers, let warnings) = response else {
            Issue.record("expected the answers to be applied, got \(response)")
            return
        }
        #expect(answers == 1)
        #expect(warnings.isEmpty)
        #expect(app.summariseRisk().execute(SummariseRiskRequest()).controlsRecorded == 1)
        let control = try #require(threats().first?.controls.first)
        #expect(control.statusId == "implemented")
    }

    @Test func movesTheScoreWhenTheFileCompensatesAThreat() throws {
        drawTheModel()
        let firstThreatId = try #require(threats().first).threatId
        let before = try #require(threats().first).riskScore
        let text = try answered(compiled(), compensate: true)

        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        // `answered` also ticks the first control of this threat, so the
        // control coverage stage takes the score from 12 to 8 before the
        // compensating control halves that 8 to 4. The threat now scores
        // lower than an unanswered one, so it no longer sorts first.
        let after = try #require(threats().first { $0.threatId == firstThreatId })
        #expect(after.riskScore < before)
        #expect(after.compensatingLabels == ["SIEM"])
        #expect(after.scoreBeforeCompensation == 8)
    }

    @Test func warnsAboutAnAnswerThisModelDoesNotRaise() throws {
        drawTheModel()
        let text = controls.write(
            ControlsSource(
                systemName: "Payments",
                answers: [
                    SourceThreatAnswer(
                        threatId: "ghost-threat",
                        sourceKind: "component",
                        sourceId: "nowhere",
                        controls: [SourceControlAnswer(description: "c", status: .implemented)]
                    )
                ]
            )
        )

        let response = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        guard case .applied(let answers, let warnings) = response else {
            Issue.record("expected the answers to be applied, got \(response)")
            return
        }
        #expect(answers == 0)
        #expect(warnings.count == 1)
        #expect(warnings[0].message.contains("ghost-threat"))
    }

    @Test func leavesAStaleAnswerOutOfTheModel() throws {
        drawTheModel()
        let source = try #require(controls.read(compiled()).source)
        let first = source.answers[0]
        let text = controls.write(
            ControlsSource(
                systemName: source.systemName,
                answers: [
                    SourceThreatAnswer(
                        threatId: first.threatId,
                        sourceKind: first.sourceKind,
                        sourceId: first.sourceId,
                        controls: [
                            SourceControlAnswer(
                                description: first.controls[0].description,
                                status: .implemented
                            )
                        ],
                        isStale: true
                    )
                ]
            )
        )

        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        #expect(app.summariseRisk().execute(SummariseRiskRequest()).controlsRecorded == 0)
    }

    @Test func refusesAFileThatDidNotParse() {
        drawTheModel()

        let response = app.applyControlAnswers().execute(
            ApplyControlAnswersRequest(text: "controls for \"P\" { threat \"t\" on gateway \"a\" { } }")
        )

        guard case .refused(let diagnostics) = response else {
            Issue.record("expected the apply to be refused, got \(response)")
            return
        }
        #expect(diagnostics.isEmpty == false)
    }

    @Test func costsOneUndo() throws {
        drawTheModel()
        let text = try answered(compiled())
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        _ = app.undoLastChange().execute(UndoLastChangeRequest())

        #expect(app.summariseRisk().execute(SummariseRiskRequest()).controlsRecorded == 0)
    }

    @Test func listsEveryThreatWithNoAnswer() {
        let response = app.checkControlAnswers().execute(
            CheckControlAnswersRequest(architectureText: payments)
        )

        guard case .checked(let unanswered, let stale, _) = response else {
            Issue.record("expected the check to run, got \(response)")
            return
        }
        #expect(response.isClean == false)
        #expect(unanswered.isEmpty == false)
        #expect(stale.isEmpty)
        #expect(unanswered[0].described.contains("has no answer"))
    }

    @Test func passesWhenEveryThreatIsAnswered() throws {
        var text = compiled()
        // Answer every control of every threat.
        let source = try #require(controls.read(text).source)
        text = controls.write(
            ControlsSource(
                systemName: source.systemName,
                catalogueTag: source.catalogueTag,
                answers: source.answers.map { answer in
                    SourceThreatAnswer(
                        threatId: answer.threatId,
                        sourceKind: answer.sourceKind,
                        sourceId: answer.sourceId,
                        controls: answer.controls.map {
                            SourceControlAnswer(description: $0.description, status: .accepted)
                        }
                    )
                }
            )
        )

        let response = app.checkControlAnswers().execute(
            CheckControlAnswersRequest(architectureText: payments, controlsText: text)
        )

        #expect(response.isClean)
    }

    @Test func reportsAStaleAnswer() throws {
        let bigger = """
        system "Payments" {
          component "api" { technology = "aws-ec2" }
          component "cache" { technology = "aws-rds" }
        }
        """
        guard case .compiled(let text, _, _, _) = app.compileControls().execute(
            CompileControlsRequest(architectureText: bigger)
        ) else {
            Issue.record("the controls did not compile")
            return
        }

        let response = app.checkControlAnswers().execute(
            CheckControlAnswersRequest(architectureText: payments, controlsText: text)
        )

        guard case .checked(_, let stale, _) = response else {
            Issue.record("expected the check to run, got \(response)")
            return
        }
        #expect(stale.isEmpty == false)
        #expect(response.isClean == false)
    }
}
