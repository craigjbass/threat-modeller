import Testing
import ThreatModelKit
import TestSupport

/// Writing the risk level a likelihood finding may answer up to.
@Suite("Setting the risk tolerance")
struct SetRiskToleranceTests {
    @Test func writesTheLevelToTheModel() {
        let app = TestDependencies()

        let response = app.setRiskTolerance()
            .execute(SetRiskToleranceRequest(level: "high"))

        #expect(response == .recorded)
        #expect(app.modelStore.current().riskTolerance == .high)
    }

    @Test func refusesALevelTheLadderDoesNotHold() {
        let app = TestDependencies()

        let response = app.setRiskTolerance()
            .execute(SetRiskToleranceRequest(level: "extreme"))

        #expect(response == .unknownLevel("extreme"))
        #expect(app.modelStore.current().riskTolerance == nil)
    }

    @Test func aSystemWithNoLevelSetReadsLow() {
        let app = TestDependencies()

        #expect(app.modelStore.current().effectiveRiskTolerance == .low)
    }

    @Test func writesRiskToleranceIntoTheArchitectureFileWithEveryOtherBlockUnchanged() {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )
        let before = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        let response = app.setRiskTolerance()
            .execute(SetRiskToleranceRequest(level: "critical"))

        #expect(response == .recorded)
        let after = app.exportArchitecture().execute(ExportArchitectureRequest()).text
        #expect(after.contains("risk_tolerance = \"critical\""))

        // Every other block the file held stands. The only change is the one
        // line the risk tolerance owns, and the blank line beside it.
        let beforeLines = Set(before.split(separator: "\n"))
        let afterLines = Set(after.split(separator: "\n"))
        #expect(afterLines.subtracting(beforeLines) == ["  risk_tolerance = \"critical\""])
    }

    @Test func theValueTheWindowShowsMatchesTheDefaultCheckReports() {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )

        let shown = ViewThreatModel(models: app.modelStore, catalogue: app.catalogueInUse)
            .execute(ViewThreatModelRequest())
            .riskTolerance

        let architectureText = app.exportArchitecture().execute(ExportArchitectureRequest()).text
        guard case .checked(_, _, _, _, _, let usedTolerance) = app.checkControlAnswers().execute(
            CheckControlAnswersRequest(architectureText: architectureText)
        ) else {
            Issue.record("the check refused the file")
            return
        }

        #expect(shown == "low")
        #expect(shown == usedTolerance)
    }

    /// The likelihood finding brings the threat's score down to a level that
    /// sits above the default `low` tolerance and inside `medium`. Raising
    /// the tolerance is the only change: the same finding answers the threat
    /// after it that it did not answer before.
    @Test func aFindingOverToleranceBecomesWithinToleranceAfterTheChange() throws {
        let app = TestDependencies()
        let added = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "confidential")
        )
        guard case .added(let componentId) = added else {
            Issue.record("the component was not added")
            return
        }

        // "misconfiguration" is medium severity on aws-ec2. On confidential
        // data that scores 2 x 3 = 6, inside the medium band and above low.
        let controlsText = """
        controls for "Untitled" {
          threat "misconfiguration" on component "\(componentId)" {
            severity = "medium"
            score    = 6

            likelihood "no in-the-wild use" {
              tier      = "commodity"
              rationale = "no known exploitation, per the vendor advisory"
            }
          }
        }
        """

        func isOverTolerance() -> Bool {
            let architectureText = app.exportArchitecture().execute(ExportArchitectureRequest()).text
            guard case .checked(let unanswered, _, _, _, _, _) = app.checkControlAnswers().execute(
                CheckControlAnswersRequest(architectureText: architectureText, controlsText: controlsText)
            ) else {
                Issue.record("the check refused the files")
                return true
            }
            return unanswered.contains { $0.threatId == "misconfiguration" }
        }

        #expect(isOverTolerance() == true)

        let response = app.setRiskTolerance().execute(SetRiskToleranceRequest(level: "medium"))
        #expect(response == .recorded)

        #expect(isOverTolerance() == false)
    }
}
