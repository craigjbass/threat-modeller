import Testing
import ThreatModelKit
import TestSupport

/// The methodology states the numbers this run actually used, so a reader can
/// check the arithmetic rather than trust it.
struct ReportMethodologyTests {
    @Test func derivesTheThresholdsFromTheScoringItself() {
        let methodology = ReportMethodology.build(zones: [], tolerance: .low)

        #expect(
            methodology.levelThresholds.map(\.label) == ["Low", "Medium", "High", "Critical"]
        )
        #expect(methodology.levelThresholds[0].lowest == 1)
        #expect(methodology.levelThresholds[0].highest == 3)
        #expect(methodology.levelThresholds[1].lowest == 4)
        #expect(methodology.levelThresholds[1].highest == 7)
        #expect(methodology.levelThresholds[2].lowest == 8)
        #expect(methodology.levelThresholds[2].highest == 11)
        #expect(methodology.levelThresholds[3].lowest == 12)
        #expect(methodology.levelThresholds[3].highest == 16)
    }

    @Test func statesTheControlCapAndTheLikelihoodTiers() {
        let methodology = ReportMethodology.build(zones: [], tolerance: .medium)

        #expect(methodology.controlCapPercent == 70)
        #expect(methodology.likelihoodTiers.map(\.label) == ["Commodity", "Targeted", "Research"])
        #expect(methodology.likelihoodTiers.map(\.count) == [100, 60, 25])
        #expect(methodology.toleranceLabel == "Medium")
    }

    @Test func namesOnlyTheZonesThatReduceRisk() {
        let reducing = ReportZone(
            name: "Private",
            networkZoneLabel: "Private",
            networkTypeLabel: "Generic",
            componentNames: [],
            riskReductionPercent: 30
        )
        let plain = ReportZone(
            name: "Public",
            networkZoneLabel: "Public",
            networkTypeLabel: "Generic",
            componentNames: [],
            riskReductionPercent: nil
        )

        let methodology = ReportMethodology.build(zones: [reducing, plain], tolerance: .low)

        #expect(methodology.zoneReductions.map(\.label) == ["Private"])
        #expect(methodology.zoneReductions.map(\.count) == [30])
    }

    @Test func riskLevelDeclaresCasesInAscendingRankOrder() {
        #expect(RiskLevel.allCases.map(\.rank) == RiskLevel.allCases.map(\.rank).sorted())
    }

    @Test func ordersTheThresholdsByRankWhateverOrderTheLevelsArriveIn() {
        let methodology = ReportMethodology.build(
            zones: [],
            tolerance: .low,
            levels: RiskLevel.allCases.reversed()
        )

        #expect(
            methodology.levelThresholds.map(\.label) == ["Low", "Medium", "High", "Critical"]
        )
    }

    @Test func theReportCarriesIt() {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        )

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.methodology.controlCapPercent == 70)
        #expect(report.methodology.toleranceLabel == "Low")
    }
}
