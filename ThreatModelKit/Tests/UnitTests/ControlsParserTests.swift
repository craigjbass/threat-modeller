import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("Reading and writing the controls language")
struct ControlsParserTests {
    private let gateway = HclControlsSource()

    private let golden = """
    controls for "Payments" {
      catalogue = "v1.0.1"

      threat "credential-theft" on component "api" {
        severity = "critical"
        score    = 90

        control "Enforce MFA on all administrative access" {
          status = "implemented"
          note   = "Okta, enforced group-wide"
        }

        control "Rotate access keys every 90 days" {
          status = "not_implemented"
        }

        compensating "Break-glass account watched by the SIEM" {
          reduces_risk_by = 40
          rationale       = "The one account left alerts on use."
        }
      }

      threat "man-in-the-middle" on flow "api->db" {
        control "Use TLS" {
          status = "accepted"
        }
      }

      threat "lateral-movement" on zone "app" {
        control "Segment the network" {
          status = "not_applicable"
        }
      }

      stale threat "sql-injection" on component "cache" {
        control "Use parameterised queries" {
          status = "implemented"
        }
      }
    }

    """

    private func errors(_ text: String) -> [Diagnostic] {
        gateway.read(text).diagnostics.filter { $0.severity == .error }
    }

    @Test func readsEveryKindOfAnswer() throws {
        let source = try #require(gateway.read(golden).source)

        #expect(source.systemName == "Payments")
        #expect(source.catalogueTag == "v1.0.1")
        #expect(source.answers.count == 4)

        let theft = try #require(source.answer(for: ThreatKey("credential-theft@component:api")))
        #expect(theft.severityLabel == "critical")
        #expect(theft.score == 90)
        #expect(theft.controls.count == 2)
        #expect(theft.controls[0].status == .implemented)
        #expect(theft.controls[0].note == "Okta, enforced group-wide")
        #expect(theft.compensating == [
            CompensatingControl(
                label: "Break-glass account watched by the SIEM",
                reducesRiskBy: 40,
                rationale: "The one account left alerts on use."
            )
        ])
    }

    @Test func readsWhatRaisedEachThreat() throws {
        let source = try #require(gateway.read(golden).source)

        #expect(source.answer(for: ThreatKey("man-in-the-middle@connection:api->db")) != nil)
        #expect(source.answer(for: ThreatKey("lateral-movement@zone:app")) != nil)
    }

    @Test func keepsAStaleAnswer() throws {
        let source = try #require(gateway.read(golden).source)

        let stale = try #require(source.answer(for: ThreatKey("sql-injection@component:cache")))
        #expect(stale.isStale)
        #expect(stale.controls[0].status == .implemented)
    }

    @Test func writesWhatItRead() throws {
        let once = try #require(gateway.read(golden).source)
        let twice = try #require(gateway.read(gateway.write(once)).source)

        #expect(once == twice)
    }

    @Test func reproducesACanonicalFileCharacterForCharacter() throws {
        let source = try #require(gateway.read(golden).source)

        #expect(gateway.write(source) == golden)
    }

    @Test func refusesAStatusItDoesNotHold() throws {
        let faults = errors("""
        controls for "P" {
          threat "t" on component "a" {
            control "c" {
              status = "maybe"
            }
          }
        }
        """)

        let fault = try #require(faults.first)
        #expect(fault.message.contains("status is \"maybe\""))
        #expect(fault.line == 4)
    }

    @Test func refusesAReductionOutsideTheRange() {
        let faults = errors("""
        controls for "P" {
          threat "t" on component "a" {
            compensating "x" {
              reduces_risk_by = 140
              rationale       = "because"
            }
          }
        }
        """)

        #expect(faults.contains { $0.message.contains("runs from 0 to 100") })
    }

    @Test func refusesACompensatingControlWithNoRationale() {
        let faults = errors("""
        controls for "P" {
          threat "t" on component "a" {
            compensating "x" {
              reduces_risk_by = 40
            }
          }
        }
        """)

        #expect(faults.contains { $0.message.contains("has no rationale") })
    }

    @Test func refusesASourceKindItDoesNotHold() {
        let faults = errors("""
        controls for "P" {
          threat "t" on gateway "a" { }
        }
        """)

        #expect(faults.contains { $0.message.contains("not \"gateway\"") })
    }

    @Test func refusesTheSameThreatAnsweredTwice() {
        let faults = errors("""
        controls for "P" {
          threat "t" on component "a" { }
          threat "t" on component "a" { }
        }
        """)

        #expect(faults.contains { $0.message.contains("answered twice") })
    }

    @Test func refusesAFileThatIsNotAControlsFile() {
        #expect(errors("system \"P\" { }").isEmpty == false)
    }

    @Test func readsAControlThatSaysNothingAsNotImplemented() throws {
        let source = try #require(gateway.read("""
        controls for "P" {
          threat "t" on component "a" {
            control "c" { }
          }
        }
        """).source)

        #expect(source.answers[0].controls[0].status == .notImplemented)
        #expect(source.answers[0].isAnswered == false)
    }
}
