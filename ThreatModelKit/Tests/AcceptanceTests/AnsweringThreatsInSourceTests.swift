import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// Given an architecture a team committed
/// When I compile the controls, answer one and compensate another
/// Then the scores follow, the report says so, and the check passes only when
/// every threat has an answer
struct AnsweringThreatsInSourceTests {
    private let app = TestDependencies()
    private let controls = HclControlsSource()

    private let payments = """
    system "Payments" {
      zone "app" {
        kind    = "private"
        network = "vpc"

        component "api" {
          technology = "aws-ec2"
          name       = "Application Server"
          data       = "confidential"
        }
      }
    }

    """

    private func compiled(_ existing: String? = nil) -> String {
        guard case .compiled(let text, _, _, _, _) = app.compileControls().execute(
            CompileControlsRequest(architectureText: payments, controlsText: existing)
        ) else {
            Issue.record("the controls did not compile")
            return ""
        }
        return text
    }

    @Test func writesEveryThreatIntoAFileAPersonFillsIn() throws {
        let source = try #require(controls.read(compiled()).source)

        #expect(source.systemName == "Payments")
        #expect(source.answers.isEmpty == false)
        #expect(source.answers.allSatisfy { $0.isAnswered == false })
        // The file reads alone: it says how bad each threat is.
        #expect(source.answers.allSatisfy { $0.severityLabel?.isEmpty == false })
    }

    @Test func carriesAnAnswerAndACompensationThroughToTheScoreAndTheReport() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let before = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first
        )

        // A person edits the compiled file: one control implemented, and the
        // same threat compensated.
        let source = try #require(controls.read(compiled()).source)
        let first = try #require(
            source.answers.first { $0.threatId == before.threatId && $0.sourceId == "api" }
        )
        let answered = controls.write(
            ControlsSource(
                systemName: source.systemName,
                catalogueTag: source.catalogueTag,
                answers: [
                    SourceThreatAnswer(
                        threatId: first.threatId,
                        sourceKind: first.sourceKind,
                        sourceId: first.sourceId,
                        severityLabel: first.severityLabel,
                        score: first.score,
                        controls: [
                            SourceControlAnswer(
                                description: first.controls[0].description,
                                status: .implemented,
                                note: "Okta, enforced group-wide"
                            )
                        ] + first.controls.dropFirst(),
                        compensating: [
                            CompensatingControl(
                                label: "Watched by the SIEM",
                                reducesRiskBy: 50,
                                rationale: "The one account left alerts on use."
                            )
                        ]
                    )
                ] + source.answers.filter { $0.key != first.key }
            )
        )

        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: answered))

        let after = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest())
                .threats.first { $0.threatId == before.threatId }
        )
        #expect(after.riskScore < before.riskScore)
        #expect(after.compensatingLabels == ["Watched by the SIEM"])
        #expect(app.summariseRisk().execute(SummariseRiskRequest()).controlsRecorded == 1)

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
        #expect(markdown.contains("- Compensated by: Watched by the SIEM (50%,"))
        #expect(markdown.contains("  - Rationale: The one account left alerts on use."))
        #expect(markdown.contains("- Controls implemented: 1"))
        #expect(markdown.contains("\u{2014} Implemented"))
    }

    @Test func failsTheCheckUntilEveryThreatIsAnswered() throws {
        #expect(
            app.checkControlAnswers().execute(
                CheckControlAnswersRequest(architectureText: payments)
            ).isClean == false
        )

        let source = try #require(controls.read(compiled()).source)
        let everythingAccepted = controls.write(
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

        #expect(
            app.checkControlAnswers().execute(
                CheckControlAnswersRequest(
                    architectureText: payments,
                    controlsText: everythingAccepted
                )
            ).isClean
        )
    }

    @Test func keepsAnAnswerWhenTheArchitectureChangesAroundIt() throws {
        let source = try #require(controls.read(compiled()).source)
        let first = source.answers[0]
        let answered = controls.write(
            ControlsSource(
                systemName: source.systemName,
                catalogueTag: source.catalogueTag,
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
                        ] + first.controls.dropFirst()
                    )
                ] + source.answers.dropFirst()
            )
        )

        // The architecture grows a component. The answer is still there.
        let bigger = payments.replacingOccurrences(
            of: "    }\n  }\n",
            with: """
                }

                component "db" {
                  technology = "aws-rds"
                  data       = "restricted"
                }
              }

            """
        )
        guard case .compiled(let text, _, _, let stale, _) = app.compileControls().execute(
            CompileControlsRequest(architectureText: bigger, controlsText: answered)
        ) else {
            Issue.record("the controls did not compile")
            return
        }

        #expect(stale == 0)
        let again = try #require(controls.read(text).source)
        #expect(
            try #require(again.answer(for: first.key)).controls
                .contains { $0.status == .implemented }
        )
        #expect(again.answers.contains { $0.sourceId == "db" })
    }
}
