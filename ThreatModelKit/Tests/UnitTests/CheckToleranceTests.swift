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
}
