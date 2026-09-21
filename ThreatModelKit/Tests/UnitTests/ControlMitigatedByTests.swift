import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

@Suite("Saying that a mitigates edge implements a control")
struct ControlMitigatedByTests {
    private let app = TestDependencies()
    private let controls = HclControlsSource()

    /// A guard and a vault that both protect a store, so the store's
    /// credential theft threat has two edges and two controls.
    private func architecture(status: String = "live") -> String {
        """
        system "Payments" {
          component "guard" {
            technology = "aws-waf"
          }

          component "vault" {
            technology = "aws-waf"
          }

          component "store" {
            technology = "aws-ec2"
            data       = "confidential"
          }

          mitigates guard -> store {
            threats = ["credential-theft"]
            status  = "\(status)"
          }

          mitigates vault -> store {
            threats = ["credential-theft"]
          }
        }

        """
    }

    private func drawTheModel(status: String = "live") {
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(text: architecture(status: status))
        )
    }

    private func compiled(_ status: String = "live") -> String {
        guard case .compiled(let text, _, _, _, _, _, _) = app.compileControls().execute(
            CompileControlsRequest(architectureText: architecture(status: status), controlsText: nil)
        ) else {
            Issue.record("the controls did not compile")
            return ""
        }
        return text
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

    /// Maps the first control to one edge.
    private func mapped(
        _ text: String,
        to edgeId: String,
        by percent: Int = 80,
        status: ControlStatus = .implemented
    ) throws -> String {
        try rewrite(text) { answer in
            [
                SourceControlAnswer(
                    description: answer.controls[0].description,
                    status: status,
                    mitigations: [ControlMitigation(edgeId: edgeId, reducesRiskBy: percent)]
                )
            ] + answer.controls.dropFirst()
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

    private func firstControl() throws -> AssessedControl {
        try #require(credentialTheft().controls.first)
    }

    // MARK: the file

    @Test func writesAMitigatedByBlockAndReadsItBack() throws {
        drawTheModel()
        let text = try mapped(compiled(), to: "guard->store")

        #expect(text.contains("mitigated_by \"guard->store\" {"))
        #expect(text.contains("reduces_risk_by = 80"))

        let read = try #require(controls.read(text).source)
        let answer = try #require(
            read.answers.first { $0.threatId == "credential-theft" && $0.sourceId == "store" }
        )
        #expect(
            answer.controls[0].mitigations
                == [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 80)]
        )
    }

    @Test func readsEveryEdgeOneControlNames() throws {
        let read = controls.read("""
        controls for "Payments" {
          threat "credential-theft" on component "store" {
            control "Rotate credentials regularly" {
              status = "implemented"

              mitigated_by "guard->store" {
                reduces_risk_by = 80
              }

              mitigated_by "vault->store" {
                reduces_risk_by = 40
              }
            }
          }
        }
        """)
        let source = try #require(read.source)

        #expect(source.answers[0].controls[0].mitigations.map(\.edgeId)
            == ["guard->store", "vault->store"])
        #expect(source.answers[0].controls[0].mitigations.map(\.reducesRiskBy) == [80, 40])
    }

    @Test func refusesAnEdgeNameWithNoArrowInIt() {
        let read = controls.read("""
        controls for "Payments" {
          threat "credential-theft" on component "store" {
            control "Rotate credentials regularly" {
              mitigated_by "guard" {
                reduces_risk_by = 80
              }
            }
          }
        }
        """)
        #expect(read.diagnostics.contains {
            $0.message == "mitigated_by names \"guard\"; a mitigates edge is named "
                + "\"<protector>-><protected>\""
        })
    }

    @Test func refusesAMappingThatSaysNothingAboutHowMuch() {
        let read = controls.read("""
        controls for "Payments" {
          threat "credential-theft" on component "store" {
            control "Rotate credentials regularly" {
              mitigated_by "guard->store" {
              }
            }
          }
        }
        """)
        #expect(read.diagnostics.contains {
            $0.message == "the mitigated_by block \"guard->store\" has no reduces_risk_by"
        })
    }

    @Test func refusesAReductionOutsideItsRange() {
        let read = controls.read("""
        controls for "Payments" {
          threat "credential-theft" on component "store" {
            control "Rotate credentials regularly" {
              mitigated_by "guard->store" {
                reduces_risk_by = 120
              }
            }
          }
        }
        """)
        #expect(read.diagnostics.contains {
            $0.message == "reduces_risk_by is 120; it runs from 0 to 100"
        })
    }

    @Test func statesWhatAMitigatedByBlockHolds() {
        #expect(
            LanguageBlockId.controlsMitigatedBy.unknownAttribute("percent")
                == "a mitigated_by block holds reduces_risk_by, not \"percent\""
        )
    }

    // MARK: what the architecture may no longer state

    @Test func refusesAnEdgeThatStatesHowMuchItTakesOff() {
        let read = HclArchitectureSource().read("""
        system "Payments" {
          component "guard" { technology = "aws-waf" }
          component "store" { technology = "aws-ec2" }

          mitigates guard -> store {
            threats         = ["credential-theft"]
            reduces_risk_by = 80
          }
        }
        """)
        #expect(read.diagnostics.contains {
            $0.message == "a mitigates edge holds threats, status and recommendation, "
                + "not \"reduces_risk_by\""
        })
    }

    @Test func readsTheStatusWordsAComponentReads() {
        let read = HclArchitectureSource().read("""
        system "Payments" {
          component "guard" { technology = "aws-waf" }
          component "store" { technology = "aws-ec2" }

          mitigates guard -> store {
            threats = ["credential-theft"]
            status  = "adopted"
          }
        }
        """)
        #expect(read.diagnostics.contains {
            $0.message == "status is \"adopted\"; a mitigates edge is \"live\" or \"proposed\""
        })
    }

    // MARK: what the model takes

    @Test func takesTheMappingALiveEdgeCarries() throws {
        drawTheModel()
        let text = try mapped(compiled(), to: "guard->store")

        let response = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))
        guard case .applied(_, let warnings) = response else {
            Issue.record("expected the answers to be applied, got \(response)")
            return
        }
        #expect(warnings.isEmpty)
        #expect(
            try firstControl().mitigations
                == [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 80)]
        )
    }

    @Test func warnsAboutAnEdgeTheSystemDoesNotDeclare() throws {
        drawTheModel()
        let text = try mapped(compiled(), to: "nothing->store")

        let response = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))
        guard case .applied(_, let warnings) = response else {
            Issue.record("expected the answers to be applied, got \(response)")
            return
        }
        #expect(warnings.contains {
            $0.message.contains(
                "names the mitigates edge \"nothing->store\", which this system does not declare"
            )
        })
        #expect(try firstControl().mitigations.isEmpty)
        #expect(try firstControl().isImplemented)
    }

    @Test func refusesToImplementAControlAProposedEdgeNames() throws {
        drawTheModel(status: "proposed")
        let text = try mapped(compiled("proposed"), to: "guard->store")

        let response = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))
        guard case .applied(_, let warnings) = response else {
            Issue.record("expected the answers to be applied, got \(response)")
            return
        }
        #expect(warnings.contains {
            $0.message.contains("the mitigates edge \"guard->store\" is proposed")
        })
        #expect(try firstControl().isImplemented == false)
        #expect(try firstControl().mitigations.isEmpty == false)
    }

    @Test func dropsAMappingWhoseEdgeTheArchitectureNoLongerDeclares() throws {
        drawTheModel()
        let text = try mapped(compiled(), to: "guard->store")
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

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

        #expect(try firstControl().mitigations.isEmpty)
        #expect(try firstControl().isImplemented)
    }

    // MARK: the score and the open count

    @Test func takesAnImplementedMappedControlOutOfTheShareOnBothSides() {
        let mapped = ResolvedControl(
            description: "Enforce IMDSv2",
            isTechnologySpecific: true,
            key: ControlKey("a"),
            isImplemented: true,
            status: .implemented,
            mitigations: [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 80)]
        )
        let unimplemented = ResolvedControl(
            description: "Enforce IMDSv2",
            isTechnologySpecific: true,
            key: ControlKey("a"),
            isImplemented: false,
            status: .notImplemented,
            mitigations: [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 80)]
        )
        let open = ResolvedControl(
            description: "Use IAM roles",
            isTechnologySpecific: true,
            key: ControlKey("b"),
            isImplemented: false,
            status: .notImplemented
        )

        #expect(ControlCoverage.coverage(of: [mapped, open]) == 0)
        // A mapping nobody has put in place is work still undone, so it stays
        // in the divisor.
        #expect(ControlCoverage.coverage(of: [unimplemented, open]) == 0)
        #expect(ControlCoverage.coverage(of: [unimplemented]) == 0)
    }

    @Test func lowersTheScoreByTheStrongestMappingAndNotTheSum() throws {
        drawTheModel()
        let unanswered = try credentialTheft().riskScore

        let text = try rewrite(compiled()) { answer in
            [
                SourceControlAnswer(
                    description: answer.controls[0].description,
                    status: .implemented,
                    mitigations: [
                        ControlMitigation(edgeId: "guard->store", reducesRiskBy: 80),
                        ControlMitigation(edgeId: "vault->store", reducesRiskBy: 40)
                    ]
                )
            ] + answer.controls.dropFirst()
        }
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        let threat = try credentialTheft()
        #expect(threat.inherentScore == unanswered)
        #expect(threat.riskScore == 2)
        #expect(threat.mitigatedByComponentReductions == [80, 40])
    }

    @Test func lowersNoScoreWhileNobodyNamesTheEdge() throws {
        drawTheModel()
        let threat = try credentialTheft()

        #expect(threat.riskScore == threat.inherentScore)
        #expect(threat.mitigatedByComponentLabels.isEmpty)
    }

    @Test func takesTheThreatOutOfTheOpenCountOnTheElement() throws {
        drawTheModel()
        #expect(ElementRiskRollup.isOpen(try credentialTheft()))

        let text = try mapped(compiled(), to: "guard->store")
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        #expect(ElementRiskRollup.isOpen(try credentialTheft()) == false)
    }

    @Test func leavesTheThreatOpenWhileTheEdgeIsProposed() throws {
        drawTheModel(status: "proposed")
        let text = try mapped(compiled("proposed"), to: "guard->store")
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        #expect(ElementRiskRollup.isOpen(try credentialTheft()))
    }

    @Test func statesTheScoreAProposedEdgeWouldReach() throws {
        drawTheModel(status: "proposed")
        let text = try mapped(compiled("proposed"), to: "guard->store")
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        let threat = try credentialTheft()
        #expect(threat.scoreIfAssumptionsHold < threat.riskScore)
    }

    // MARK: the window's writer

    @Test func offersEveryEdgeThatAnswersTheThreatOnTheElement() throws {
        drawTheModel()
        let threat = try credentialTheft()

        #expect(threat.mitigatesEdgeChoices.map(\.id).sorted()
            == ["guard->store", "vault->store"])
        #expect(threat.mitigatesEdgeChoices.first { $0.id == "guard->store" }?.label == "WAF")
    }

    @Test func recordsTheControlAsImplementedWhenAPersonNamesALiveEdge() throws {
        drawTheModel()
        let key = try firstControl().key

        #expect(
            app.setControlMitigatedBy().execute(
                SetControlMitigatedByRequest(
                    controlKey: key,
                    edgeId: "guard->store",
                    reducesRiskBy: 80
                )
            ) == .recorded
        )

        let control = try #require(credentialTheft().controls.first { $0.key == key })
        #expect(control.mitigations == [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 80)])
        #expect(control.isImplemented)
    }

    @Test func holdsEveryEdgeAPersonNames() throws {
        drawTheModel()
        let key = try firstControl().key

        _ = app.setControlMitigatedBy().execute(
            SetControlMitigatedByRequest(controlKey: key, edgeId: "guard->store", reducesRiskBy: 80)
        )
        _ = app.setControlMitigatedBy().execute(
            SetControlMitigatedByRequest(controlKey: key, edgeId: "vault->store", reducesRiskBy: 40)
        )

        let control = try #require(credentialTheft().controls.first { $0.key == key })
        #expect(control.mitigations.map(\.edgeId) == ["guard->store", "vault->store"])
    }

    @Test func changesHowMuchOneEdgeTakesOff() throws {
        drawTheModel()
        let key = try firstControl().key
        _ = app.setControlMitigatedBy().execute(
            SetControlMitigatedByRequest(controlKey: key, edgeId: "guard->store", reducesRiskBy: 80)
        )

        _ = app.setControlMitigatedBy().execute(
            SetControlMitigatedByRequest(controlKey: key, edgeId: "guard->store", reducesRiskBy: 20)
        )

        let control = try #require(credentialTheft().controls.first { $0.key == key })
        #expect(control.mitigations == [ControlMitigation(edgeId: "guard->store", reducesRiskBy: 20)])
    }

    @Test func takesOneMappingOffAndKeepsTheOther() throws {
        drawTheModel()
        let key = try firstControl().key
        _ = app.setControlMitigatedBy().execute(
            SetControlMitigatedByRequest(controlKey: key, edgeId: "guard->store", reducesRiskBy: 80)
        )
        _ = app.setControlMitigatedBy().execute(
            SetControlMitigatedByRequest(controlKey: key, edgeId: "vault->store", reducesRiskBy: 40)
        )

        _ = app.setControlMitigatedBy().execute(
            SetControlMitigatedByRequest(controlKey: key, edgeId: "guard->store", reducesRiskBy: nil)
        )

        let control = try #require(credentialTheft().controls.first { $0.key == key })
        #expect(control.mitigations.map(\.edgeId) == ["vault->store"])
    }

    @Test func refusesAnEdgeTheModelDoesNotHold() throws {
        drawTheModel()
        #expect(
            app.setControlMitigatedBy().execute(
                SetControlMitigatedByRequest(
                    controlKey: try firstControl().key,
                    edgeId: "nothing->store",
                    reducesRiskBy: 80
                )
            ) == .unknownEdge
        )
    }

    @Test func refusesAReductionTheLanguageDoesNotRead() throws {
        drawTheModel()
        #expect(
            app.setControlMitigatedBy().execute(
                SetControlMitigatedByRequest(
                    controlKey: try firstControl().key,
                    edgeId: "guard->store",
                    reducesRiskBy: 101
                )
            ) == .outOfRange
        )
    }

    @Test func leavesAControlOpenWhileTheEdgeItNamesIsProposed() throws {
        drawTheModel(status: "proposed")
        let key = try firstControl().key

        #expect(
            app.setControlMitigatedBy().execute(
                SetControlMitigatedByRequest(
                    controlKey: key,
                    edgeId: "guard->store",
                    reducesRiskBy: 80
                )
            ) == .recorded
        )

        let control = try #require(credentialTheft().controls.first { $0.key == key })
        #expect(control.isImplemented == false)
        #expect(control.mitigations.isEmpty == false)
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
        #expect(threat.controls.contains { $0.mitigatedBy == ["WAF (80%)"] })
    }
}
