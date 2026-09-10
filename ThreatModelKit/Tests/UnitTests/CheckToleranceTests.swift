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
}
