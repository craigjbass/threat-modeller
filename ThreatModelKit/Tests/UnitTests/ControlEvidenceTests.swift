import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

@Suite("What proves a control is in place")
struct ControlEvidenceTests {
    @Test func ordersTheFiveTiersWeakestFirst() {
        #expect(
            ControlEvidence.allCases.sorted().map(\.rawValue)
                == ["asserted", "documented", "configured", "tested", "audited"]
        )
        #expect(ControlEvidence.asserted < ControlEvidence.audited)
    }

    @Test func readsNoTierFromAWordItDoesNotHold() {
        #expect(ControlEvidence(rawValue: "believed") == nil)
        #expect(
            ControlEvidence.wordsItHolds
                == "\"asserted\", \"documented\", \"configured\", \"tested\", \"audited\""
        )
    }

    @Test func saysWhatTheReportPrints() throws {
        let verified = try #require(try? GovernanceDate.read("2026-09-01").get())

        #expect(
            ControlProof(evidence: .tested, reference: "ci/mfa-test", verifiedOn: verified).says
                == "tested, ci/mfa-test, verified 2026-09-01"
        )
        #expect(ControlProof(evidence: .asserted).says == "asserted")
        #expect(ControlProof().says == "no evidence")
        #expect(ControlProof().isEmpty)
    }
}

@Suite("Evidence in a controls file")
struct ControlEvidenceLanguageTests {
    private let gateway = HclControlsSource()

    private let golden = """
    controls for "Payments" {
      threat "credential-theft" on component "api" {
        control "Enforce MFA on all administrative access" {
          status      = "implemented"
          note        = "Okta, enforced group-wide"
          evidence    = "tested"
          reference   = "ci/okta-mfa-enforced-test"
          verified_on = "2026-09-01"
        }

        compensating "Watched by the SIEM" {
          reduces_risk_by = 50
          rationale       = "The one account left alerts on use."
          evidence        = "configured"
          reference       = "splunk/saved-search/admin-login"
          verified_on     = "2026-08-30"
        }
      }
    }

    """

    private func errors(_ text: String) -> [String] {
        gateway.read(text).diagnostics.filter { $0.severity == .error }.map(\.message)
    }

    @Test func readsTheThreeAttributes() throws {
        let source = try #require(gateway.read(golden).source)
        let answer = try #require(source.answers.first)

        let control = try #require(answer.controls.first)
        #expect(control.proof.evidence == .tested)
        #expect(control.proof.reference == "ci/okta-mfa-enforced-test")
        #expect(control.proof.verifiedOn?.description == "2026-09-01")

        let compensating = try #require(answer.compensating.first)
        #expect(compensating.proof.evidence == .configured)
        #expect(compensating.proof.verifiedOn?.description == "2026-08-30")
    }

    @Test func writesThemBackWithNoDiff() throws {
        let source = try #require(gateway.read(golden).source)

        #expect(gateway.write(source) == golden)
    }

    @Test func readsAControlThatStatesNoneOfThemAndWritesNoneBack() throws {
        let text = """
        controls for "Payments" {
          threat "credential-theft" on component "api" {
            control "Enforce MFA on all administrative access" {
              status = "implemented"
            }
          }
        }

        """
        let source = try #require(gateway.read(text).source)

        #expect(source.answers.first?.controls.first?.proof.isEmpty == true)
        #expect(gateway.write(source) == text)
    }

    @Test func refusesATierItDoesNotHold() {
        #expect(
            errors("""
            controls for "P" {
              threat "t" on component "api" {
                control "A control" {
                  evidence = "believed"
                }
              }
            }
            """) == [
                "evidence is \"believed\"; this application holds \"asserted\", \"documented\", "
                    + "\"configured\", \"tested\", \"audited\""
            ]
        )
    }

    @Test func refusesADateThatIsNotTheShape() {
        #expect(
            errors("""
            controls for "P" {
              threat "t" on component "api" {
                control "A control" {
                  verified_on = "01-09-2026"
                }
              }
            }
            """) == ["verified_on is \"01-09-2026\"; a date is written YYYY-MM-DD"]
        )
    }

    @Test func refusesADateThatIsNotADay() {
        #expect(
            errors("""
            controls for "P" {
              threat "t" on component "api" {
                control "A control" {
                  verified_on = "2026-02-30"
                }
              }
            }
            """) == ["verified_on is \"2026-02-30\", which is not a date"]
        )
    }
}

@Suite("What check does about evidence")
struct EvidenceCheckTests {
    private let app = TestDependencies()

    private func payments(rule: String? = nil) -> String {
        """
        system "Payments" {
        \(rule.map { "  requires_evidence_above = \"\($0)\"\n" } ?? "")
          component "api" {
            technology = "aws-ec2"
            data       = "confidential"
          }
        }
        """
    }

    private func answers(evidence: String? = nil) -> String {
        let proof = evidence.map { "\n          evidence = \"\($0)\"" } ?? ""
        return """
        controls for "Payments" {
          threat "credential-theft" on component "api" {
            control "Enforce IMDSv2 to block SSRF-based credential theft" {
              status = "implemented"\(proof)
            }

            control "Use IAM roles with minimal permissions" {
              status = "implemented"\(proof)
            }
          }
        }
        """
    }

    private func failures(rule: String?, evidence: String?) -> [String] {
        let response = app.checkControlAnswers().execute(
            CheckControlAnswersRequest(
                architectureText: payments(rule: rule),
                controlsText: answers(evidence: evidence),
                tolerance: "critical"
            )
        )
        guard case .checked(_, _, _, let governance, _, _) = response else {
            Issue.record("expected the answers to be checked, got \(response)")
            return []
        }
        return governance
    }

    @Test func failsNothingForAProjectThatStatesNoRule() {
        #expect(failures(rule: nil, evidence: nil).isEmpty)
    }

    @Test func failsAnImplementedControlAboveTheLevelWithNoEvidence() {
        let failed = failures(rule: "high", evidence: nil)

        #expect(failed.count == 2)
        #expect(
            failed.contains(
                "credential-theft@component:api: \"Enforce IMDSv2 to block SSRF-based "
                    + "credential theft\" is implemented above high risk with no evidence"
            )
        )
    }

    @Test func passesTheSameControlWithATier() {
        #expect(failures(rule: "high", evidence: "tested").isEmpty)
    }

    /// The level is read before the controls. Both controls being in place
    /// lowers the residual score below high, and the rule still catches them:
    /// the question is what the threat is worth if they are not really there.
    @Test func readsTheLevelBeforeTheControls() {
        #expect(failures(rule: "critical", evidence: nil).isEmpty == false)
    }

    @Test func refusesALevelTheApplicationDoesNotHold() {
        let read = HclArchitectureSource().read(payments(rule: "enormous"))

        #expect(
            read.diagnostics.map(\.message) == [
                "requires_evidence_above is \"enormous\"; this application holds "
                    + "\"low\", \"medium\", \"high\", \"critical\""
            ]
        )
    }
}
