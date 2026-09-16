import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

@Suite("What the risk tolerance does to a check")
struct CheckToleranceTests {
    private let app = TestDependencies()

    private func controls(score: Int, tolerance: String) -> String {
        """
        controls for "ClearanceKit" {
          tolerance = "\(tolerance)"

          threat "sip-bypass" on component "laptop" {
            severity = "critical"
            score    = \(score)

            likelihood "no in-the-wild use" {
              tier      = "research"
              rationale = "every bypass was researcher-found"
            }
          }
        }
        """
    }

    @Test func aFindingAnswersAThreatInsideTheTolerance() throws {
        let source = try #require(HclControlsSource().read(controls(score: 3, tolerance: "low")).source)
        #expect(source.answers.first?.isAnswered(within: .low) == true)
    }

    @Test func aFindingAnswersNothingAboveTheTolerance() throws {
        let source = try #require(HclControlsSource().read(controls(score: 6, tolerance: "low")).source)
        #expect(source.answers.first?.isAnswered(within: .low) == false)
        #expect(source.answers.first?.isAnswered(within: .medium) == true)
    }

    @Test func aThreatWithNoFindingStillNeedsAnAnswer() throws {
        let plain = """
        controls for "ClearanceKit" {
          threat "sip-bypass" on component "laptop" {
            severity = "critical"
            score    = 2
          }
        }
        """
        let source = try #require(HclControlsSource().read(plain).source)
        #expect(source.answers.first?.isAnswered(within: .critical) == false)
    }

    @Test func theFileStatesTheToleranceTheCheckUses() throws {
        let source = try #require(HclControlsSource().read(controls(score: 3, tolerance: "medium")).source)
        #expect(source.riskTolerance == "medium")
    }

    // The low band runs 1-3 and the medium band starts at 4, so these two
    // pin the edge exactly: 3 is the last score low covers, 4 is the first
    // score it does not.
    @Test func aResidualScoreOfThreeAnswersAtLow() throws {
        let source = try #require(HclControlsSource().read(controls(score: 3, tolerance: "low")).source)
        #expect(source.answers.first?.isAnswered(within: .low) == true)
    }

    @Test func aResidualScoreOfFourDoesNotAnswerAtLow() throws {
        let source = try #require(HclControlsSource().read(controls(score: 4, tolerance: "low")).source)
        #expect(source.answers.first?.isAnswered(within: .low) == false)
    }

    @Test func aToleranceTheRiskLadderDoesNotHoldRecordsOneError() {
        let read = HclControlsSource().read(controls(score: 3, tolerance: "extreme"))
        #expect(read.diagnostics.filter { $0.severity == .error }.count == 1)
    }

    // A tree the architecture no longer supports is work for a person, so a
    // check fails while one remains.

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

    private func check(trees: String?) -> CheckControlAnswersResponse {
        app.checkControlAnswers().execute(
            CheckControlAnswersRequest(
                architectureText: twoTier,
                controlsText: nil,
                attackTreeText: trees,
                tolerance: "critical"
            )
        )
    }

    @Test func failsWhileATreeNoLongerBinds() {
        let response = check(trees: """
        attack_trees for "P" {
          tree "t" {
            goal "misconfiguration" on component "db"
            step "credential-theft" on component "gone"
          }
        }
        """)

        guard case .checked(_, _, let staleTrees, _, _, _) = response else {
            Issue.record("the check refused: \(response)")
            return
        }
        #expect(staleTrees == ["the tree \"t\" is written but no longer binds"])
        #expect(response.isClean == false)
    }

    @Test func failsWhileOneLinkOfAChainNoLongerBinds() {
        let response = check(trees: """
        attack_trees for "P" {
          tree "t" {
            goal "misconfiguration" on component "db"

            then {
              step "dos-attack" on component "api"
              step "credential-theft" on component "gone"
              step "misconfiguration" on component "api"
            }
          }
        }
        """)

        guard case .checked(_, _, let staleTrees, _, _, _) = response else {
            Issue.record("the check refused: \(response)")
            return
        }
        #expect(staleTrees == ["the tree \"t\" is written but no longer binds"])
        #expect(response.isClean == false)
    }

    @Test func passesForATreeThatStillBinds() {
        let response = check(trees: """
        attack_trees for "P" {
          tree "t" {
            goal "misconfiguration" on component "db"
            step "credential-theft" on component "api"
          }
        }
        """)

        guard case .checked(_, _, let staleTrees, _, _, _) = response else {
            Issue.record("the check refused: \(response)")
            return
        }
        #expect(staleTrees.isEmpty)
    }

    @Test func passesForASystemWithNoTreeFile() {
        guard case .checked(_, _, let staleTrees, _, _, _) = check(trees: nil) else {
            Issue.record("the check refused")
            return
        }
        #expect(staleTrees.isEmpty)
    }

}
