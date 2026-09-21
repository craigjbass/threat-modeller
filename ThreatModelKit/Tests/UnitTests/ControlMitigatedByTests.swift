import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

@Suite("Saying that a mitigates edge implements a control")
struct ControlMitigatedByTests {
    private let app = TestDependencies()
    private let controls = HclControlsSource()

    /// A guard that protects a store, so the store's credential theft threat
    /// has both an edge and a pair of controls.
    private func architecture(status: String = "adopted") -> String {
        """
        system "Payments" {
          component "guard" {
            technology = "aws-waf"
          }

          component "store" {
            technology = "aws-ec2"
            data       = "confidential"
          }

          mitigates guard -> store {
            threats         = ["credential-theft"]
            reduces_risk_by = 80
            status          = "\(status)"
          }
        }

        """
    }

    private func drawTheModel(status: String = "adopted") {
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(text: architecture(status: status))
        )
    }

    private func compiled(_ status: String = "adopted") -> String {
        guard case .compiled(let text, _, _, _, _, _, _) = app.compileControls().execute(
            CompileControlsRequest(architectureText: architecture(status: status), controlsText: nil)
        ) else {
            Issue.record("the controls did not compile")
            return ""
        }
        return text
    }

    /// Writes `mitigated_by` onto the first control of the store's credential
    /// theft answer, and leaves every other answer as it was.
    private func mapped(
        _ text: String,
        to edgeId: String,
        status: ControlStatus = .implemented
    ) throws -> String {
        try rewrite(text) { answer in
            [
                SourceControlAnswer(
                    description: answer.controls[0].description,
                    status: status,
                    mitigatedBy: edgeId
                )
            ] + answer.controls.dropFirst()
        }
    }

    /// Rewrites the controls of the store's credential theft answer.
    private func rewrite(
        _ text: String,
        _ controlsOf: (SourceThreatAnswer) -> [SourceControlAnswer]
    ) throws -> String {
        let source = try #require(controls.read(text).source)
        let index = try #require(
            source.answers.firstIndex {
                $0.threatId == "credential-theft" && $0.sourceId == "store"
            }
        )
        let answer = source.answers[index]
        var answers = source.answers
        answers[index] = SourceThreatAnswer(
            threatId: answer.threatId,
            sourceKind: answer.sourceKind,
            sourceId: answer.sourceId,
            severityLabel: answer.severityLabel,
            score: answer.score,
            controls: controlsOf(answer),
            compensating: answer.compensating
        )
        return controls.write(
            ControlsSource(
                systemName: source.systemName,
                catalogueTag: source.catalogueTag,
                answers: answers
            )
        )
    }

    /// Answers the first control without naming an edge.
    private func mappedNothing(_ text: String, status: ControlStatus) throws -> String {
        try rewrite(text) { answer in
            [
                SourceControlAnswer(description: answer.controls[0].description, status: status)
            ] + answer.controls.dropFirst()
        }
    }

    /// Maps the first control to the edge and implements the second.
    private func both(_ text: String, mapping edgeId: String) throws -> String {
        try rewrite(text) { answer in
            [
                SourceControlAnswer(
                    description: answer.controls[0].description,
                    status: .implemented,
                    mitigatedBy: edgeId
                ),
                SourceControlAnswer(
                    description: answer.controls[1].description,
                    status: .implemented
                )
            ] + answer.controls.dropFirst(2)
        }
    }

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    private func credentialTheft() throws -> AssessedThreat {
        try #require(
            threats().first {
                $0.threatId == "credential-theft" && $0.source.id == "component:store"
            }
        )
    }

    // MARK: the file

    @Test func writesTheEdgeAControlNamesAndReadsItBack() throws {
        drawTheModel()
        let text = try mapped(compiled(), to: "guard->store")

        #expect(text.contains("mitigated_by = \"guard->store\""))

        let read = try #require(controls.read(text).source)
        let answer = try #require(
            read.answers.first { $0.threatId == "credential-theft" && $0.sourceId == "store" }
        )
        #expect(answer.controls[0].mitigatedBy == "guard->store")
    }

    @Test func refusesAnEdgeNameWithNoArrowInIt() throws {
        let read = controls.read("""
        controls for "Payments" {
          threat "credential-theft" on component "store" {
            control "Rotate credentials regularly" {
              status       = "implemented"
              mitigated_by = "guard"
            }
          }
        }
        """)
        #expect(read.diagnostics.contains {
            $0.message == "mitigated_by is \"guard\"; a mitigates edge is named \"<protector>-><protected>\""
        })
    }

    @Test func offersMitigatedByAsAnAttributeOfAControl() {
        let block = LanguageBlockId.controlsControl.block
        #expect(block.attributes.contains("mitigated_by"))
        #expect(
            LanguageBlockId.controlsControl.unknownAttribute("mitigates")
                == "a control holds status, note, mitigated_by, evidence, reference and "
                    + "verified_on, not \"mitigates\""
        )
    }

    // MARK: what the model takes

    @Test func takesTheMappingAnAdoptedEdgeCarries() throws {
        drawTheModel()
        let text = try mapped(compiled(), to: "guard->store")

        let response = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))
        guard case .applied(_, let warnings) = response else {
            Issue.record("expected the answers to be applied, got \(response)")
            return
        }
        #expect(warnings.isEmpty)

        let threat = try credentialTheft()
        #expect(threat.controls.first { $0.mitigatedByEdgeId == "guard->store" } != nil)
    }

    @Test func warnsAboutAnEdgeTheSystemDoesNotDeclare() throws {
        drawTheModel()
        let text = try mapped(compiled(), to: "vault->store")

        let response = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))
        guard case .applied(_, let warnings) = response else {
            Issue.record("expected the answers to be applied, got \(response)")
            return
        }
        #expect(warnings.contains {
            $0.message.contains("names the mitigates edge \"vault->store\", which this system does not declare")
        })

        let threat = try credentialTheft()
        #expect(threat.controls.allSatisfy { $0.mitigatedByEdgeId == nil })
        #expect(threat.controls.contains { $0.isImplemented })
    }

    @Test func warnsAboutAnEdgeThatAnswersAnotherThreat() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: """
        system "Payments" {
          component "guard" {
            technology = "aws-waf"
          }

          component "store" {
            technology = "aws-ec2"
            data       = "confidential"
          }

          mitigates guard -> store {
            threats         = ["dos-attack"]
            reduces_risk_by = 80
          }
        }

        """))
        guard case .compiled(let compiledText, _, _, _, _, _, _) = app.compileControls().execute(
            CompileControlsRequest(
                architectureText: """
                system "Payments" {
                  component "guard" {
                    technology = "aws-waf"
                  }

                  component "store" {
                    technology = "aws-ec2"
                    data       = "confidential"
                  }

                  mitigates guard -> store {
                    threats         = ["dos-attack"]
                    reduces_risk_by = 80
                  }
                }

                """,
                controlsText: nil
            )
        ) else {
            Issue.record("the controls did not compile")
            return
        }
        let text = try mapped(compiledText, to: "guard->store")

        let response = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))
        guard case .applied(_, let warnings) = response else {
            Issue.record("expected the answers to be applied, got \(response)")
            return
        }
        #expect(warnings.contains {
            $0.message == "the mitigates edge \"guard->store\" does not answer \"credential-theft\" "
                + "on component \"store\", so the mapping is not applied"
        })
        #expect(try credentialTheft().controls.allSatisfy { $0.mitigatedByEdgeId == nil })
    }

    @Test func refusesToImplementAControlAnAssumedEdgeNames() throws {
        drawTheModel(status: "assumed")
        let text = try mapped(compiled("assumed"), to: "guard->store")

        let response = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))
        guard case .applied(_, let warnings) = response else {
            Issue.record("expected the answers to be applied, got \(response)")
            return
        }
        #expect(warnings.contains {
            $0.message.contains("the mitigates edge \"guard->store\" is assumed")
        })
        #expect(try credentialTheft().controls.allSatisfy { $0.isImplemented == false })
    }

    @Test func dropsAMappingWhoseEdgeTheArchitectureNoLongerDeclares() throws {
        drawTheModel()
        let text = try mapped(compiled(), to: "guard->store")
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        // The same file, against an architecture with no edge at all.
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: """
        system "Payments" {
          component "guard" {
            technology = "aws-waf"
          }

          component "store" {
            technology = "aws-ec2"
            data       = "confidential"
          }
        }

        """))
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        let threat = try credentialTheft()
        #expect(threat.controls.allSatisfy { $0.mitigatedByEdgeId == nil })
        #expect(threat.controls.contains { $0.isImplemented })
    }

    // MARK: the score and the open count

    @Test func takesAMappedControlOutOfTheShareOnBothSides() {
        let mapped = ResolvedControl(
            description: "Enforce IMDSv2",
            isTechnologySpecific: true,
            key: ControlKey("a"),
            isImplemented: true,
            status: .implemented,
            mitigatedByEdgeId: "guard->store"
        )
        let open = ResolvedControl(
            description: "Use IAM roles",
            isTechnologySpecific: true,
            key: ControlKey("b"),
            isImplemented: false,
            status: .notImplemented
        )
        let ticked = ResolvedControl(
            description: "Use IAM roles",
            isTechnologySpecific: true,
            key: ControlKey("b"),
            isImplemented: true,
            status: .implemented
        )

        // The mapped control counts on neither side, so one open control is
        // the whole divisor and nothing is implemented.
        #expect(ControlCoverage.coverage(of: [mapped, open]) == 0)
        // The same pair without the mapping gives the mapped control its
        // share, which is the double count this rule takes out.
        #expect(
            ControlCoverage.coverage(of: [
                ResolvedControl(
                    description: "Enforce IMDSv2",
                    isTechnologySpecific: true,
                    key: ControlKey("a"),
                    isImplemented: true,
                    status: .implemented
                ),
                open
            ]) == 0.5
        )
        // A mapped control leaves the divisor, so the one control a person
        // ticked is the whole share.
        #expect(ControlCoverage.coverage(of: [mapped, ticked]) == 1)
    }

    @Test func scoresAThreatWhoseControlsAreMappedAndTicked() throws {
        drawTheModel()
        #expect(try credentialTheft().riskScore == 2)

        let text = try both(compiled(), mapping: "guard->store")
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        // One control mapped and one ticked: the share is one of one, so the
        // controls take the whole cap and the edge takes its 80% after them.
        let threat = try credentialTheft()
        #expect(threat.inherentScore == 12)
        #expect(threat.riskScore == 1)
    }

    @Test func takesTheThreatOutOfTheOpenCountOnTheElement() throws {
        drawTheModel()
        let open = ElementRiskRollup.byElement(threats(), levelOrder: [])
        #expect(open["component:store"]?.openCount ?? 0 > 0)

        let text = try mapped(compiled(), to: "guard->store")
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        let threat = try credentialTheft()
        #expect(ElementRiskRollup.isOpen(threat) == false)
    }

    @Test func leavesTheThreatOpenWhileTheEdgeIsAssumed() throws {
        drawTheModel(status: "assumed")
        let text = try mapped(compiled("assumed"), to: "guard->store")
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        #expect(ElementRiskRollup.isOpen(try credentialTheft()))
    }

    // MARK: the window's writer

    @Test func offersEveryEdgeThatAnswersTheThreatOnTheElement() throws {
        drawTheModel()
        let threat = try credentialTheft()
        #expect(threat.mitigatesEdgeChoices.map(\.id) == ["guard->store"])
        #expect(threat.mitigatesEdgeChoices.first?.label == "WAF (80%)")
    }

    @Test func recordsTheControlAsImplementedWhenAPersonPicksAnAdoptedEdge() throws {
        drawTheModel()
        let key = try #require(credentialTheft().controls.first?.key)

        let response = app.setControlMitigatedBy().execute(
            SetControlMitigatedByRequest(controlKey: key, edgeId: "guard->store")
        )
        #expect(response == .recorded)

        let control = try #require(credentialTheft().controls.first { $0.key == key })
        #expect(control.mitigatedByEdgeId == "guard->store")
        #expect(control.isImplemented)
    }

    @Test func takesTheMappingOffAgain() throws {
        drawTheModel()
        let key = try #require(credentialTheft().controls.first?.key)
        _ = app.setControlMitigatedBy().execute(
            SetControlMitigatedByRequest(controlKey: key, edgeId: "guard->store")
        )

        #expect(
            app.setControlMitigatedBy().execute(
                SetControlMitigatedByRequest(controlKey: key, edgeId: nil)
            ) == .recorded
        )
        let control = try #require(credentialTheft().controls.first { $0.key == key })
        #expect(control.mitigatedByEdgeId == nil)
    }

    @Test func refusesAnEdgeTheModelDoesNotHold() throws {
        drawTheModel()
        let key = try #require(credentialTheft().controls.first?.key)
        #expect(
            app.setControlMitigatedBy().execute(
                SetControlMitigatedByRequest(controlKey: key, edgeId: "vault->store")
            ) == .unknownEdge
        )
    }

    @Test func refusesAnAssumedEdge() throws {
        drawTheModel(status: "assumed")
        let key = try #require(credentialTheft().controls.first?.key)
        #expect(
            app.setControlMitigatedBy().execute(
                SetControlMitigatedByRequest(controlKey: key, edgeId: "guard->store")
            ) == .edgeIsAssumed
        )
    }

    // MARK: the report

    @Test func namesWhatImplementsAControlInTheThreatStanza() throws {
        drawTheModel()
        let text = try mapped(compiled(), to: "guard->store")
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
        let threat = try #require(
            report.threats.first { $0.threatId == "credential-theft" && $0.sourceName == "EC2" }
        )
        #expect(threat.controls.contains { $0.mitigatedBy == "WAF" })
    }
}
