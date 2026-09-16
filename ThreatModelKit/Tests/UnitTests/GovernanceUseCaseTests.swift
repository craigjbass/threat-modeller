import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// Writing the governance file from the compiled answers.
@Suite("Compiling the governance a system needs")
struct CompileGovernanceTests {
    private let controls = HclControlsSource()
    private let governance = HclGovernanceSource()

    private func compile(
        controlsText: String,
        governanceText: String? = nil,
        actions: [String] = []
    ) -> CompileGovernanceResponse {
        CompileGovernance(controlsSources: controls, governanceSources: governance)
            .execute(
                CompileGovernanceRequest(
                    controlsText: controlsText,
                    governanceText: governanceText,
                    actionLabels: actions
                )
            )
    }

    private func text(of response: CompileGovernanceResponse) -> String? {
        guard case .compiled(let text, _, _) = response else {
            Issue.record("expected the governance to compile, got \(response)")
            return nil
        }
        return text
    }

    private let accepting = """
    controls for "Payments" {
      threat "credential-theft" on component "api" {
        control "Enforce MFA" {
          status = "accepted"
        }
      }
    }
    """

    private let implementing = """
    controls for "Payments" {
      threat "credential-theft" on component "api" {
        control "Enforce MFA" {
          status = "implemented"
        }
      }
    }
    """

    @Test func writesNoFileForASystemThatGovernsNothing() {
        #expect(text(of: compile(controlsText: implementing)) == nil)
    }

    @Test func writesAnEmptyStanzaForAnUngovernedAcceptedControl() throws {
        let written = try #require(text(of: compile(controlsText: accepting)))

        #expect(written.contains("threat \"credential-theft\" on component \"api\" {"))
        #expect(written.contains("accepted \"Enforce MFA\" {"))
        #expect(written.contains("owner") == false)
    }

    @Test func keepsAGovernedStanzaWhole() throws {
        let existing = """
        governance for "Payments" {
          threat "credential-theft" on component "api" {
            accepted "Enforce MFA" {
              owner       = "Head of Platform"
              accepted_on = "2026-09-01"
              review_by   = "2027-03-01"
            }
          }
        }
        """

        let written = try #require(
            text(of: compile(controlsText: accepting, governanceText: existing))
        )

        #expect(written.contains("owner       = \"Head of Platform\""))
        #expect(written.contains("review_by   = \"2027-03-01\""))
        #expect(written.contains("stale") == false)
    }

    @Test func writesAnEmptyStanzaForAnUngovernedRecommendation() throws {
        let written = try #require(text(of: compile(controlsText: """
        controls for "Payments" {
          threat "credential-theft" on component "api" {
            recommendation "Protect the plist" {
              note = "The MDM daemon owns it."
            }
          }
        }
        """)))

        #expect(written.contains("work \"Protect the plist\" {"))
    }

    @Test func writesAnEmptyStanzaForAnUngovernedAction() throws {
        let written = try #require(
            text(of: compile(controlsText: implementing, actions: ["reenable-devtool-rules"]))
        )

        #expect(written.contains("action \"reenable-devtool-rules\" {"))
    }

    @Test func marksAControlThatIsNoLongerAcceptedStale() throws {
        let existing = """
        governance for "Payments" {
          threat "credential-theft" on component "api" {
            accepted "Enforce MFA" {
              owner = "Head of Platform"
            }
          }
        }
        """

        let written = try #require(
            text(of: compile(controlsText: implementing, governanceText: existing))
        )

        // The threat is still raised, so its block is live and the stanza
        // for the control nobody accepts now is the stale one.
        #expect(written.contains("threat \"credential-theft\" on component \"api\" {"))
        #expect(written.contains("stale threat") == false)
        #expect(written.contains("stale accepted \"Enforce MFA\" {"))
    }

    @Test func marksAGoneActionStale() throws {
        let existing = """
        governance for "Payments" {
          action "gone" {
            owner = "Endpoint team"
          }
        }
        """

        let written = try #require(
            text(of: compile(controlsText: accepting, governanceText: existing))
        )

        #expect(written.contains("stale action \"gone\" {"))
    }

    @Test func marksAThreatTheArchitectureNoLongerRaisesStale() throws {
        let existing = """
        governance for "Payments" {
          threat "sql-injection" on component "gone" {
            accepted "Use parameterised queries" {
              owner = "Somebody"
            }
          }
        }
        """

        let written = try #require(
            text(of: compile(controlsText: accepting, governanceText: existing))
        )

        #expect(written.contains("stale threat \"sql-injection\" on component \"gone\" {"))
    }

    /// Section 8.3: nothing deletes a stale block. Everything a person wrote
    /// into one is still in the file after the compile marks it stale.
    @Test func keepsEveryAttributeOnAStaleThreatBlock() throws {
        let existing = """
        governance for "Payments" {
          threat "sql-injection" on component "gone" {
            accepted "Use parameterised queries" {
              owner       = "Head of Data"
              accepted_on = "2026-01-05"
              review_by   = "2026-07-05"
              rationale   = "the query runs against one read-only replica"
              sources     = ["https://example.com/risk-register/RSK-9"]
            }

            work "Write the runbook" {
              owner      = "Data team"
              effort     = "small"
              due_by     = "2026-11-30"
              status     = "in_progress"
              acceptance = "The runbook names the owner."
              note       = "The rollout waits on the migration."
            }
          }
        }
        """

        let written = try #require(
            text(of: compile(controlsText: accepting, governanceText: existing))
        )
        let source = try #require(governance.read(written).source)
        let threat = try #require(
            source.threat(for: ThreatKey("sql-injection@component:gone"))
        )

        #expect(threat.isStale)
        let risk = try #require(threat.accepted.first)
        #expect(risk.isStale)
        #expect(risk.owner == "Head of Data")
        #expect(risk.acceptedOn == "2026-01-05")
        #expect(risk.reviewBy == "2026-07-05")
        #expect(risk.rationale == "the query runs against one read-only replica")
        #expect(risk.sources == ["https://example.com/risk-register/RSK-9"])
        let work = try #require(threat.work.first)
        #expect(work.isStale)
        #expect(work.owner == "Data team")
        #expect(work.effort == "small")
        #expect(work.dueBy == "2026-11-30")
        #expect(work.status == "in_progress")
        #expect(work.acceptance == "The runbook names the owner.")
        #expect(work.note == "The rollout waits on the migration.")
    }

    /// Issue #144. A flow's block keys on the resolver's word `connection`,
    /// so a second compile finds the block the first compile wrote and keeps
    /// the owner, rather than writing a second block with the same key.
    @Test func keepsTheOwnerOfAFlowThreatAndWritesOneBlock() throws {
        let acceptingOnAFlow = """
        controls for "Payments" {
          threat "connection-mitm" on flow "api->db" {
            control "Enforce TLS" {
              status = "accepted"
            }
          }
        }
        """
        let existing = """
        governance for "Payments" {
          threat "connection-mitm" on flow "api->db" {
            accepted "Enforce TLS" {
              owner     = "Head of Platform"
              review_by = "2027-03-01"
            }
          }
        }
        """

        let written = try #require(
            text(of: compile(controlsText: acceptingOnAFlow, governanceText: existing))
        )
        let read = governance.read(written)

        #expect(read.diagnostics.map(\.message) == [], "the compile wrote:\n\(written)")
        let source = try #require(read.source)
        #expect(source.threats.count == 1)
        let risk = try #require(source.threats.first?.accepted.first)
        #expect(risk.owner == "Head of Platform")
        #expect(risk.reviewBy == "2027-03-01")
        #expect(risk.isStale == false)
        #expect(written.contains("stale") == false)
    }

    @Test func writesTheSameBytesTwice() throws {
        let first = try #require(text(of: compile(controlsText: accepting)))
        let second = try #require(
            text(of: compile(controlsText: accepting, governanceText: first))
        )

        #expect(second == first)
    }

    @Test func refusesAGovernanceFileThatDoesNotParse() {
        guard case .refused(let diagnostics) = compile(
            controlsText: accepting,
            governanceText: "governance of \"P\" { }"
        ) else {
            Issue.record("expected the file to be refused")
            return
        }
        #expect(diagnostics.isEmpty == false)
    }
}

/// What `check` says about an accepted risk.
@Suite("Checking the governance of an accepted risk")
struct CheckGovernanceTests {
    private let controls = HclControlsSource()
    private let governance = HclGovernanceSource()
    /// 1970-01-12, which every date in these tests is measured against.
    private let clock = FixedClock()

    private let accepting = """
    controls for "Payments" {
      threat "credential-theft" on component "api" {
        control "Enforce MFA" {
          status = "accepted"
        }
      }
    }
    """

    private func failures(_ governanceText: String?) -> [String] {
        let response = CheckGovernance(
            controlsSources: controls,
            governanceSources: governance,
            clock: clock
        ).execute(
            CheckGovernanceRequest(controlsText: accepting, governanceText: governanceText)
        )
        guard case .checked(let failures) = response else {
            Issue.record("expected the governance to be checked, got \(response)")
            return []
        }
        return failures
    }

    private func governed(_ body: String) -> String {
        """
        governance for "Payments" {
          threat "credential-theft" on component "api" {
            accepted "Enforce MFA" {
        \(body)
            }
          }
        }
        """
    }

    @Test func failsForAnAcceptedControlWithNoStanza() {
        #expect(
            failures(nil) == [
                "credential-theft@component:api is accepted and has no governance entry;"
                    + " run threatmodeller compile"
            ]
        )
    }

    @Test func failsForAnAcceptedRiskWithNoOwner() {
        #expect(
            failures(governed("      review_by = \"2027-03-01\"")) == [
                "credential-theft@component:api is accepted by nobody;"
                    + " the accepted risk needs an owner"
            ]
        )
    }

    @Test func failsForAnAcceptedRiskWithNoReviewDate() {
        #expect(
            failures(governed("      owner = \"Head of Platform\"")) == [
                "credential-theft@component:api is accepted with no review date"
            ]
        )
    }

    @Test func failsForAReviewDateThatHasPassed() {
        // The fixed clock stands at 1970-01-12.
        #expect(
            failures(
                governed("""
                      owner     = "Head of Platform"
                      review_by = "1970-01-01"
                """)
            ) == [
                "credential-theft@component:api was accepted for review by 1970-01-01,"
                    + " which has passed"
            ]
        )
    }

    @Test func passesForAReviewDateStillToCome() {
        #expect(
            failures(
                governed("""
                      owner     = "Head of Platform"
                      review_by = "2027-03-01"
                """)
            ).isEmpty
        )
    }

    @Test func failsNothingForPlannedWorkWithNoOwner() {
        let response = CheckGovernance(
            controlsSources: controls,
            governanceSources: governance,
            clock: clock
        ).execute(
            CheckGovernanceRequest(
                controlsText: """
                controls for "Payments" {
                  threat "credential-theft" on component "api" {
                    recommendation "Protect the plist" { }
                  }
                }
                """,
                governanceText: """
                governance for "Payments" {
                  threat "credential-theft" on component "api" {
                    work "Protect the plist" { }
                  }
                }
                """
            )
        )

        guard case .checked(let failures) = response else {
            Issue.record("expected the governance to be checked")
            return
        }
        #expect(failures.isEmpty)
    }

    @Test func failsNothingForAStaleStanza() {
        let response = CheckGovernance(
            controlsSources: controls,
            governanceSources: governance,
            clock: clock
        ).execute(
            CheckGovernanceRequest(
                controlsText: """
                controls for "Payments" {
                  stale threat "credential-theft" on component "gone" {
                    control "Enforce MFA" {
                      status = "accepted"
                    }
                  }
                }
                """,
                governanceText: """
                governance for "Payments" {
                  stale threat "credential-theft" on component "gone" {
                    stale accepted "Enforce MFA" { }
                  }
                }
                """
            )
        )

        guard case .checked(let failures) = response else {
            Issue.record("expected the governance to be checked")
            return
        }
        #expect(failures.isEmpty)
    }

    @Test func readsTheDayTheClockNames() {
        #expect(
            CheckGovernance.today(Date(timeIntervalSince1970: 1_000_000)).description
                == "1970-01-12"
        )
    }
}

/// What the governance file puts onto the model, and what the report and the
/// threat card then read.
@Suite("Applying a governance file to a model")
struct ApplyGovernanceTests {
    private let models = InMemoryThreatModelGateway()
    private let sources = HclGovernanceSource()

    private func apply(_ text: String) -> ApplyGovernanceResponse {
        ApplyGovernance(models: models, sources: sources)
            .execute(ApplyGovernanceRequest(text: text))
    }

    @Test func putsAnAcceptedRiskOntoTheModel() throws {
        let response = apply("""
        governance for "P" {
          threat "credential-theft" on component "api" {
            accepted "Enforce MFA" {
              owner       = "Head of Platform"
              accepted_on = "2026-09-01"
              review_by   = "2027-03-01"
              rationale   = "The rollout waits on SSO."
            }
          }
        }
        """)

        #expect(response == .applied(accepted: 1, work: 0))
        let key = ThreatKey(threatId: "credential-theft", sourceId: "component:api")
        let accepted = try #require(models.current().acceptedRisks[key]?.first)
        #expect(accepted.owner == "Head of Platform")
        #expect(accepted.reviewBy?.description == "2027-03-01")
        #expect(accepted.rationale == "The rollout waits on SSO.")
    }

    @Test func putsPlannedWorkAndAnActionOntoTheModel() throws {
        _ = apply("""
        governance for "P" {
          threat "credential-theft" on component "api" {
            work "Protect the plist" {
              owner  = "Platform team"
              effort = "medium"
              due_by = "2026-11-30"
              status = "in_progress"
            }
          }

          action "reenable-devtool-rules" {
            owner = "Endpoint team"
          }
        }
        """)

        let key = ThreatKey(threatId: "credential-theft", sourceId: "component:api")
        let work = try #require(models.current().plannedWork[key]?.first)
        #expect(work.owner == "Platform team")
        #expect(work.effort == .medium)
        #expect(work.status == .inProgress)
        #expect(work.says == "Platform team, medium effort, due 2026-11-30, in progress")

        let action = try #require(models.current().actionWork["reenable-devtool-rules"])
        #expect(action.owner == "Endpoint team")
        #expect(action.says == "Endpoint team, planned")
    }

    @Test func readsNothingFromAStaleStanza() {
        _ = apply("""
        governance for "P" {
          stale threat "gone" on component "api" {
            accepted "A control" {
              owner = "Somebody"
            }
          }

          threat "credential-theft" on component "api" {
            stale accepted "Another control" {
              owner = "Somebody"
            }
          }
        }
        """)

        #expect(models.current().acceptedRisks.isEmpty)
    }

    @Test func statesNothingForAStanzaThatStatesNothing() {
        #expect(PlannedWork(label: "Do the thing").says == nil)
    }

    @Test func refusesAFileThatDoesNotParse() {
        guard case .refused(let diagnostics) = apply("governance of \"P\" { }") else {
            Issue.record("expected the file to be refused")
            return
        }
        #expect(diagnostics.isEmpty == false)
    }

    @Test func saysWhenAnAcceptedRiskIsPastItsReviewDate() throws {
        let past = try #require(try? GovernanceDate.read("2026-01-01").get())
        let today = try #require(try? GovernanceDate.read("2026-09-14").get())
        let risk = RiskAcceptance(control: "A control", owner: "Somebody", reviewBy: past)

        #expect(risk.isOverdue(on: today))
        #expect(RiskAcceptance(control: "A control").isOverdue(on: today) == false)
    }
}
