import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("Reading and writing the governance language")
struct GovernanceParserTests {
    private let gateway = HclGovernanceSource()

    private let golden = """
    governance for "Payments" {
      threat "credential-theft" on component "api" {
        accepted "Enforce MFA on all administrative access" {
          owner       = "Head of Platform"
          accepted_on = "2026-09-01"
          review_by   = "2027-03-01"
          rationale   = "The MFA rollout waits on the SSO migration."
          sources     = ["https://example.com/risk-register/RSK-412"]
        }

        work "Protect the managed preferences plist" {
          owner      = "Platform team"
          effort     = "medium"
          due_by     = "2026-11-30"
          acceptance = "The plist is writable only by the MDM daemon."
        }
      }

      action "reenable-devtool-rules" {
        owner      = "Endpoint team"
        effort     = "small"
        due_by     = "2026-10-15"
        status     = "in_progress"
        acceptance = "The read rules are on, and the audit log shows no bypass."
      }
    }

    """

    private func errors(_ text: String) -> [String] {
        gateway.read(text).diagnostics.filter { $0.severity == .error }.map(\.message)
    }

    @Test func readsEveryBlockTheDesignStates() throws {
        let source = try #require(gateway.read(golden).source)

        #expect(source.systemName == "Payments")
        let threat = try #require(source.threats.first)
        #expect(threat.key.value == "credential-theft@component:api")
        #expect(threat.isStale == false)

        let accepted = try #require(threat.accepted.first)
        #expect(accepted.control == "Enforce MFA on all administrative access")
        #expect(accepted.owner == "Head of Platform")
        #expect(accepted.acceptedOn == "2026-09-01")
        #expect(accepted.reviewBy == "2027-03-01")
        #expect(accepted.rationale == "The MFA rollout waits on the SSO migration.")
        #expect(accepted.sources == ["https://example.com/risk-register/RSK-412"])

        let work = try #require(threat.work.first)
        #expect(work.label == "Protect the managed preferences plist")
        #expect(work.owner == "Platform team")
        #expect(work.effort == "medium")
        #expect(work.dueBy == "2026-11-30")
        #expect(work.status == "planned")

        let action = try #require(source.actions.first)
        #expect(action.label == "reenable-devtool-rules")
        #expect(action.status == "in_progress")
    }

    @Test func writesItBackWithNoDiff() throws {
        let source = try #require(gateway.read(golden).source)

        #expect(gateway.write(source) == golden)
    }

    @Test func readsAStaleStanzaAndKeepsItStale() throws {
        let source = try #require(gateway.read("""
        governance for "P" {
          stale threat "gone" on component "api" {
            stale accepted "A control nobody accepts now" {
              owner = "Somebody"
            }
          }

          stale action "gone-action" {
            owner = "Somebody"
          }
        }
        """).source)

        let threat = try #require(source.threats.first)
        #expect(threat.isStale)
        #expect(threat.accepted.first?.isStale == true)
        #expect(source.actions.first?.isStale == true)
    }

    @Test func writesAStaleStanzaBackUnchanged() throws {
        let text = """
        governance for "P" {
          stale threat "gone" on component "api" {
            stale accepted "A control nobody accepts now" {
              owner = "Somebody"
            }
          }
        }

        """
        let source = try #require(gateway.read(text).source)

        #expect(gateway.write(source) == text)
    }

    // Every row of the table in section 3.5 of the design.

    @Test func refusesADateThatIsNotTheShape() {
        #expect(
            errors("""
            governance for "P" {
              threat "t" on component "api" {
                accepted "A control" {
                  review_by = "01-09-2026"
                }
              }
            }
            """) == ["review_by is \"01-09-2026\"; a date is written YYYY-MM-DD"]
        )
    }

    @Test func refusesADateThatIsNotADay() {
        #expect(
            errors("""
            governance for "P" {
              threat "t" on component "api" {
                accepted "A control" {
                  accepted_on = "2026-02-30"
                }
              }
            }
            """) == ["accepted_on is \"2026-02-30\", which is not a date"]
        )
    }

    @Test func refusesAnEffortOutsideTheThree() {
        #expect(
            errors("""
            governance for "P" {
              action "a" {
                effort = "enormous"
              }
            }
            """) == ["effort is \"enormous\"; this application holds \"small\", \"medium\", \"large\""]
        )
    }

    @Test func refusesAStatusOutsideTheFour() {
        #expect(
            errors("""
            governance for "P" {
              action "a" {
                status = "maybe"
              }
            }
            """) == [
                "status is \"maybe\"; this application holds \"planned\", \"in_progress\", "
                    + "\"done\", \"dropped\""
            ]
        )
    }

    @Test func refusesAThreatBlockWithNoOn() {
        #expect(
            errors("""
            governance for "P" {
              threat "t" {
              }
            }
            """).first == "a threat says what raised it: on component, on zone or on flow"
        )
    }

    @Test func refusesTwoBlocksWithOneKey() {
        #expect(
            errors("""
            governance for "P" {
              threat "t" on component "api" { }
              threat "t" on component "api" { }
            }
            """) == ["t@component:api is governed twice"]
        )
    }

    @Test func refusesAFileThatDoesNotStartWithGovernance() {
        #expect(errors("controls for \"P\" { }").first == "expected governance, not \"controls\"")
    }

    @Test func refusesABlockMissingFor() {
        #expect(errors("governance of \"P\" { }").first == "expected for, not \"of\"")
    }
}

@Suite("A date a governance file states")
struct GovernanceDateTests {
    @Test func readsACalendarDate() throws {
        let date = try #require(try? GovernanceDate.read("2026-09-01").get())

        #expect(date.year == 2026)
        #expect(date.month == 9)
        #expect(date.day == 1)
        #expect(date.description == "2026-09-01")
    }

    @Test(arguments: ["01-09-2026", "2026-9-1", "2026/09/01", "tomorrow", ""])
    func refusesTextThatIsNotTheShape(_ raw: String) {
        #expect(GovernanceDate.read(raw) == .failure(.notTheShape))
    }

    @Test(arguments: ["2026-02-30", "2026-13-01", "2026-00-10", "2026-04-31"])
    func refusesADayTheCalendarDoesNotHold(_ raw: String) {
        #expect(GovernanceDate.read(raw) == .failure(.notADay))
    }

    @Test func readsALeapDayInALeapYearAndRefusesItOtherwise() {
        #expect((try? GovernanceDate.read("2024-02-29").get()) != nil)
        #expect(GovernanceDate.read("2026-02-29") == .failure(.notADay))
        #expect((try? GovernanceDate.read("2000-02-29").get()) != nil)
        #expect(GovernanceDate.read("1900-02-29") == .failure(.notADay))
    }

    @Test func ordersTwoDates() throws {
        let earlier = try #require(try? GovernanceDate.read("2026-09-01").get())
        let later = try #require(try? GovernanceDate.read("2027-03-01").get())

        #expect(earlier < later)
        #expect(later > earlier)
    }

    @Test func countsTheDaysFromOneDateToAnother() throws {
        func date(_ raw: String) throws -> GovernanceDate {
            try #require(try? GovernanceDate.read(raw).get())
        }

        #expect(try date("2026-01-01").daysUntil(date("2026-01-11")) == 10)
        #expect(try date("2026-01-11").daysUntil(date("2026-01-01")) == -10)
        #expect(try date("2026-01-01").daysUntil(date("2026-01-01")) == 0)
        #expect(try date("2024-02-28").daysUntil(date("2024-03-01")) == 2)
        #expect(try date("2023-02-28").daysUntil(date("2023-03-01")) == 1)
        #expect(try date("1900-12-31").daysUntil(date("1901-01-01")) == 1)
        #expect(try date("2000-12-31").daysUntil(date("2001-01-01")) == 1)
    }
}
