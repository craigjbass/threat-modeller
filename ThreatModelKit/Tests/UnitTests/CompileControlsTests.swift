import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

@Suite("Compiling the controls a model's threats need")
struct CompileControlsTests {
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

    private let withACache = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "cache" {
        technology = "aws-rds"
        data       = "internal"
      }
    }

    """

    private func compile(
        _ architecture: String,
        _ existing: String? = nil
    ) -> CompileControlsResponse {
        app.compileControls().execute(
            CompileControlsRequest(architectureText: architecture, controlsText: existing)
        )
    }

    private func text(of response: CompileControlsResponse) -> String {
        guard case .compiled(let text, _, _, _) = response else {
            Issue.record("expected the controls to compile, got \(response)")
            return ""
        }
        return text
    }

    @Test func writesEveryThreatWithEveryControlUnanswered() throws {
        let response = compile(payments)

        guard case .compiled(let text, let answered, let unanswered, let stale) = response else {
            Issue.record("expected the controls to compile, got \(response)")
            return
        }
        #expect(answered == 0)
        #expect(unanswered > 0)
        #expect(stale == 0)

        let source = try #require(controls.read(text).source)
        #expect(source.systemName == "Payments")
        #expect(source.answers.isEmpty == false)
        #expect(source.answers.allSatisfy { $0.isStale == false })
        #expect(source.answers.allSatisfy { answer in
            answer.controls.allSatisfy { $0.status == .notImplemented }
        })
    }

    @Test func writesTheSeverityAndTheScoreForTheReader() throws {
        let source = try #require(controls.read(text(of: compile(payments))).source)

        let answer = try #require(source.answers.first)
        #expect(answer.severityLabel?.isEmpty == false)
        #expect((answer.score ?? 0) > 0)
    }

    @Test func keepsAnAnswerWhoseThreatIsStillRaised() throws {
        let first = text(of: compile(payments))
        let answered = try answerTheFirstControl(in: first)

        let again = try #require(controls.read(text(of: compile(payments, answered))).source)

        let answer = try #require(again.answers.first)
        #expect(answer.controls.first?.status == .implemented)
        #expect(answer.controls.first?.note == "Okta, enforced group-wide")
    }

    @Test func keepsACompensatingControl() throws {
        let first = text(of: compile(payments))
        var source = try #require(controls.read(first).source)
        let original = source.answers[0]
        source = ControlsSource(
            systemName: source.systemName,
            catalogueTag: source.catalogueTag,
            answers: [
                SourceThreatAnswer(
                    threatId: original.threatId,
                    sourceKind: original.sourceKind,
                    sourceId: original.sourceId,
                    controls: original.controls,
                    compensating: [
                        CompensatingControl(label: "SIEM", reducesRiskBy: 40, rationale: "It alerts.")
                    ]
                )
            ] + source.answers.dropFirst()
        )

        let again = try #require(
            controls.read(text(of: compile(payments, controls.write(source)))).source
        )

        #expect(again.answers.first?.compensating.first?.label == "SIEM")
    }

    @Test func movesAnAnswerTheArchitectureNoLongerRaisesIntoStale() throws {
        let withCache = text(of: compile(withACache))
        let answered = try answerACacheControl(in: withCache)

        let response = compile(payments, answered)

        guard case .compiled(let text, _, _, let stale) = response else {
            Issue.record("expected the controls to compile, got \(response)")
            return
        }
        #expect(stale > 0)
        let source = try #require(controls.read(text).source)
        let staleAnswers = source.answers.filter(\.isStale)
        #expect(staleAnswers.isEmpty == false)
        #expect(staleAnswers.allSatisfy { $0.sourceId == "cache" })
        // Nothing deletes a person's work.
        #expect(staleAnswers.contains { answer in
            answer.controls.contains { $0.status == .implemented }
        })
    }

    @Test func movesAStaleAnswerBackWhenItsThreatIsRaisedAgain() throws {
        let withCache = text(of: compile(withACache))
        let answered = try answerACacheControl(in: withCache)
        let staled = text(of: compile(payments, answered))

        let again = try #require(controls.read(text(of: compile(withACache, staled))).source)

        #expect(again.answers.allSatisfy { $0.isStale == false })
        #expect(
            again.answers.contains { answer in
                answer.sourceId == "cache" && answer.controls.contains { $0.status == .implemented }
            }
        )
    }

    @Test func writesTheFileItReadWhenNothingChanged() throws {
        let first = text(of: compile(payments))

        let second = text(of: compile(payments, first))

        #expect(second == first)
    }

    @Test func keepsALikelihoodFindingAndASeverityDecisionThroughACompile() throws {
        let first = text(of: compile(payments))
        let edited = first.replacingOccurrences(
            of: "  score",
            with: """
              likelihood "no in-the-wild use" {
                tier      = "research"
                rationale = "every bypass was researcher-found"
                sources   = ["CVE-2021-30892"]
              }

              severity_override "high" {
                rationale = "the exploit reads"
              }

              score
            """
        )

        let again = text(of: compile(payments, edited))

        #expect(again.contains("likelihood \"no in-the-wild use\""))
        #expect(again.contains("severity_override \"high\""))
        #expect(again.contains("CVE-2021-30892"))
    }

    /// The architecture alone never carries a likelihood finding, a severity
    /// decision, a compensating control or an implemented control's status.
    /// A compile that ignores the file it read would always write the raw
    /// score, and a likelihood finding could never answer a threat.
    @Test func aLikelihoodFindingLowersTheScoreTheNextTimeItCompiles() throws {
        let existing = """
        controls for "Payments" {
          threat "misconfiguration" on component "api" {
            severity = "medium"
            score    = 6

            likelihood "no in-the-wild use" {
              tier      = "research"
              rationale = "every bypass was researcher-found"
            }
          }
        }
        """

        let source = try #require(controls.read(text(of: compile(payments, existing))).source)
        let misconfiguration = try #require(source.answers.first { $0.threatId == "misconfiguration" })

        // Medium (2) times confidential (3) is 6; "research" cuts that to 2.
        #expect(misconfiguration.score == 2)
        #expect(misconfiguration.likelihood?.likelihood == .research)
    }

    @Test func refusesAnArchitectureThatDidNotParse() {
        let response = compile("system \"P\" { component \"a\" { } }")

        guard case .refused(let diagnostics) = response else {
            Issue.record("expected the compile to be refused, got \(response)")
            return
        }
        #expect(diagnostics.isEmpty == false)
    }

    @Test func refusesAControlsFileThatDidNotParse() {
        let response = compile(payments, "controls for \"P\" { threat \"t\" on gateway \"a\" { } }")

        guard case .refused(let diagnostics) = response else {
            Issue.record("expected the compile to be refused, got \(response)")
            return
        }
        #expect(diagnostics.isEmpty == false)
    }

    @Test func changesNothingOnScreen() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 0, y: 0, sensitivity: "internal")
        )

        _ = compile(payments)

        #expect(
            app.viewThreatModel().execute(ViewThreatModelRequest())
                .components.map(\.technologyId) == ["aws-rds"]
        )
    }

    // MARK: helpers

    private func answerTheFirstControl(in text: String) throws -> String {
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
                    note: "Okta, enforced group-wide"
                )
            ] + first.controls.dropFirst(),
            compensating: first.compensating
        )
        return controls.write(
            ControlsSource(
                systemName: source.systemName,
                catalogueTag: source.catalogueTag,
                answers: [answered] + source.answers.dropFirst()
            )
        )
    }

    private func answerACacheControl(in text: String) throws -> String {
        let source = try #require(controls.read(text).source)
        let answers = source.answers.map { answer -> SourceThreatAnswer in
            guard answer.sourceId == "cache", let control = answer.controls.first else {
                return answer
            }
            return SourceThreatAnswer(
                threatId: answer.threatId,
                sourceKind: answer.sourceKind,
                sourceId: answer.sourceId,
                severityLabel: answer.severityLabel,
                score: answer.score,
                controls: [
                    SourceControlAnswer(description: control.description, status: .implemented)
                ] + answer.controls.dropFirst(),
                compensating: answer.compensating
            )
        }
        return controls.write(
            ControlsSource(
                systemName: source.systemName,
                catalogueTag: source.catalogueTag,
                answers: answers
            )
        )
    }
}
