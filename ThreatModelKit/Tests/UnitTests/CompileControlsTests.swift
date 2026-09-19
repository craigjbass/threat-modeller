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
        guard case .compiled(let text, _, _, _, _, _, _) = response else {
            Issue.record("expected the controls to compile, got \(response)")
            return ""
        }
        return text
    }

    @Test func writesEveryThreatWithEveryControlUnanswered() throws {
        let response = compile(payments)

        guard case .compiled(let text, let answered, let unanswered, let stale, _, _, _) = response else {
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

        guard case .compiled(let text, _, _, let stale, _, _, _) = response else {
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

    @Test func aModelWithNoStatedToleranceCompilesAtLow() throws {
        let text = text(of: compile(payments))

        #expect(text.contains("tolerance = \"low\""))
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

    /// I2: a compile carries `ApplyControlAnswers`'s warnings out, so a
    /// `severity_override` naming a severity the catalogue does not hold is
    /// not silently dropped.
    @Test func carriesTheSeverityOverrideWarningThroughACompile() throws {
        let existing = """
        controls for "Payments" {
          threat "misconfiguration" on component "api" {
            severity = "medium"
            score    = 6

            severity_override "not-a-real-severity" {
              rationale = "a typo in the severity id"
            }
          }
        }
        """

        let response = compile(payments, existing)

        guard case .compiled(_, _, _, _, _, _, let warnings) = response else {
            Issue.record("expected the controls to compile, got \(response)")
            return
        }
        #expect(warnings.count == 1)
        #expect(warnings[0].message.contains("not-a-real-severity"))
    }

    // GAP: a `.controls` file states the catalogue tag it was written
    // against, and a compile overwrote that tag with the one in use on every
    // run, with no warning, the way a `.lib` file drifting does warn.

    @Test func warnsWhenAControlsFileSCatalogueTagIsNotTheTagInUse() throws {
        let existing = """
        controls for "Payments" {
          catalogue = "v0.9.0"
        }
        """

        let response = compile(payments, existing)

        guard case .compiled(_, _, _, _, _, _, let warnings) = response else {
            Issue.record("expected the controls to compile, got \(response)")
            return
        }
        #expect(
            warnings.map(\.message).contains(
                "the controls file was written against catalogue v0.9.0, "
                    + "and the catalogue in use is v0.0.0"
            )
        )
    }

    @Test func warnsAboutNothingWhenAControlsFileSTagMatches() throws {
        let existing = """
        controls for "Payments" {
          catalogue = "v0.0.0"
        }
        """

        let response = compile(payments, existing)

        guard case .compiled(_, _, _, _, _, _, let warnings) = response else {
            Issue.record("expected the controls to compile, got \(response)")
            return
        }
        #expect(warnings.isEmpty)
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

    // The trees a person wrote, bound against the model and written back.

    private let twoTier = """
    system "P" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "db" {
        technology = "aws-rds"
        data       = "restricted"
      }

      flow api -> db
    }
    """

    private func compile(
        architecture: String,
        controls: String? = nil,
        trees: String? = nil
    ) -> CompileControlsResponse {
        app.compileControls().execute(
            CompileControlsRequest(
                architectureText: architecture,
                controlsText: controls,
                attackTreeText: trees
            )
        )
    }

    @Test func writesATreeStanzaForABoundTree() {
        let response = compile(architecture: twoTier, trees: """
        attack_trees for "P" {
          tree "t" {
            raises_risk_by = 40

            goal "misconfiguration" on component "db"
            step "credential-theft" on component "api"
          }
        }
        """)

        guard case .compiled(let text, _, _, _, let staleTrees, _, _) = response else {
            Issue.record("the compile refused: \(response)")
            return
        }
        #expect(text.contains("tree \"t\" {"))
        #expect(text.contains("step \"credential-theft@component:api\" {"))
        #expect(text.contains("goal           = \"misconfiguration@component:db\""))
        #expect(text.contains("raises_risk_by = 40"))
        #expect(staleTrees == 0)
    }

    /// The stanza states each link's position, so a reader of the compiled
    /// file sees the order without the `.attacktree` file.
    @Test func writesThePositionOfEachLinkOfAChain() {
        let response = compile(architecture: twoTier, trees: """
        attack_trees for "P" {
          tree "t" {
            goal "misconfiguration" on component "db"

            then {
              step "dos-attack" on component "api"
              step "credential-theft" on component "api"
              step "misconfiguration" on component "api"
            }
          }
        }
        """)

        guard case .compiled(let text, _, _, _, let staleTrees, _, _) = response else {
            Issue.record("the compile refused: \(response)")
            return
        }
        #expect(staleTrees == 0)
        #expect(text.contains("""
            step "dos-attack@component:api" {
              state    = "open"
              position = 1
            }

            step "credential-theft@component:api" {
              state    = "open"
              position = 2
            }

            step "misconfiguration@component:api" {
              state    = "open"
              position = 3
            }
        """))

        // The compiled file reads back with the order it states.
        let read = HclControlsSource().read(text)
        #expect(read.source?.trees.first?.steps.map(\.position) == [1, 2, 3])
    }

    /// A sufficient control that is implemented closes the tree as a whole:
    /// the stanza names it, states each named control, and the chain is 0.
    @Test func writesTheSufficientControlThatClosedTheTree() throws {
        let response = compile(
            architecture: twoTier,
            controls: """
            controls for "P" {
              threat "credential-theft" on component "api" {
                control "Enforce IMDSv2 to block SSRF-based credential theft" { status = "implemented" }
              }
            }
            """,
            trees: """
            attack_trees for "P" {
              tree "t" {
                raises_risk_by = 40
                closed_by      = ["Enforce IMDSv2 to block SSRF-based credential theft", "Apply rate limits"]

                goal "misconfiguration" on component "db"
                step "credential-theft" on component "api"
              }
            }
            """
        )

        guard case .compiled(let text, _, _, _, let staleTrees, _, _) = response else {
            Issue.record("the compile refused: \(response)")
            return
        }
        #expect(text.contains("closed_by      = \"Enforce IMDSv2 to block SSRF-based credential theft\""))
        #expect(text.contains("chain          = 0"))
        #expect(text.contains(
            "sufficient \"Enforce IMDSv2 to block SSRF-based credential theft\" {\n      state = \"closes\"\n    }"
        ))
        #expect(text.contains("sufficient \"Apply rate limits\" {\n      state = \"open\"\n    }"))
        #expect(staleTrees == 0)

        let read = try #require(HclControlsSource().read(text).source?.trees.first)
        #expect(read.closedBy == "Enforce IMDSv2 to block SSRF-based credential theft")
        #expect(read.sufficient.map(\.state) == ["closes", "open"])
    }

    @Test func movesATreeIntoStaleWhenASufficientControlIsUnknown() {
        let response = compile(architecture: twoTier, trees: """
        attack_trees for "P" {
          tree "t" {
            closed_by = ["Rotate credentails regularly"]

            goal "misconfiguration" on component "db"
            step "credential-theft" on component "api"
          }
        }
        """)

        guard case .compiled(let text, _, _, _, let staleTrees, _, _) = response else {
            Issue.record("the compile refused: \(response)")
            return
        }
        #expect(text.contains("stale tree \"t\" {"))
        #expect(text.contains("sufficient \"Rotate credentails regularly\" {\n      state = \"unknown\"\n    }"))
        #expect(staleTrees == 1)
    }

    @Test func movesATreeIntoStaleWhenAStepNoLongerBinds() {
        let response = compile(architecture: twoTier, trees: """
        attack_trees for "P" {
          tree "t" {
            goal "misconfiguration" on component "db"
            step "credential-theft" on component "gone"
          }
        }
        """)

        guard case .compiled(let text, _, _, _, let staleTrees, _, _) = response else {
            Issue.record("the compile refused: \(response)")
            return
        }
        #expect(text.contains("stale tree \"t\" {"))
        #expect(staleTrees == 1)
    }

    @Test func deletesAStanzaForATreeThePersonDeleted() {
        let existing = """
        controls for "P" {
          tree "gone" {
            goal = "g@component:db"

            step "a@component:api" {
              state = "open"
            }
          }
        }
        """

        let response = compile(architecture: twoTier, controls: existing)

        guard case .compiled(let text, _, _, _, let staleTrees, _, _) = response else {
            Issue.record("the compile refused: \(response)")
            return
        }
        #expect(text.contains("tree \"gone\"") == false)
        #expect(staleTrees == 0)
    }

    @Test func writesTheSameBytesTwiceForOneProject() {
        let trees = """
        attack_trees for "P" {
          tree "t" {
            raises_risk_by = 40

            goal "misconfiguration" on component "db"
            step "credential-theft" on component "api"
          }
        }
        """

        guard case .compiled(let first, _, _, _, _, _, _) = compile(
            architecture: twoTier,
            trees: trees
        ) else {
            Issue.record("the first compile refused")
            return
        }
        guard case .compiled(let second, _, _, _, _, _, _) = compile(
            architecture: twoTier,
            controls: first,
            trees: trees
        ) else {
            Issue.record("the second compile refused")
            return
        }

        #expect(second == first)
    }

    @Test func refusesATreeFileThatDoesNotParse() {
        let response = compile(architecture: twoTier, trees: "attack_trees for \"P\" { colour }")

        guard case .refused(let diagnostics) = response else {
            Issue.record("expected the tree file to be refused")
            return
        }
        #expect(diagnostics.isEmpty == false)
    }

}
