import Testing
import ThreatModelKit

struct PathwayMitigationTests {
    @Test func startsWithTheMasterToggleOff() {
        let settings = PathwayMitigationSettings()

        // A model must not score lower than the catalogue says until the user
        // states the mitigation is real on their system.
        #expect(settings.isMasterEnabled == false)
        #expect(settings.configs.isEmpty)
    }

    @Test func startsEachMitigationEnabledAtHalfReduction() {
        let settings = PathwayMitigationSettings()
        let config = settings.config(for: PathwayMitigationId("waf-protection"))

        #expect(config == PathwayMitigationSettings.defaultConfig)
        #expect(config.isEnabled)
        #expect(config.mode == .reduce)
        #expect(config.reductionPercent == 50)
    }

    @Test func remembersTheConfigTheUserSet() {
        let id = PathwayMitigationId("waf-protection")
        let settings = PathwayMitigationSettings(
            isMasterEnabled: true,
            configs: [id: PathwayMitigationConfig(isEnabled: false, mode: .remove, reductionPercent: 90)]
        )

        let config = settings.config(for: id)
        #expect(config.isEnabled == false)
        #expect(config.mode == .remove)
        #expect(config.reductionPercent == 90)
    }

    @Test func dropsAThreatEntirelyInRemoveMode() {
        #expect(PathwayMitigation.outcome(score: 12, mode: .remove, percent: 0) == .removed)
        #expect(PathwayMitigation.outcome(score: 1, mode: .remove, percent: 90) == .removed)
    }

    @Test func lowersAScoreInReduceMode() {
        // max(1, floor(score - score * percent / 100)). Spec section 5.3.
        #expect(PathwayMitigation.outcome(score: 12, mode: .reduce, percent: 50) == .reduced(to: 6))
        #expect(PathwayMitigation.outcome(score: 12, mode: .reduce, percent: 25) == .reduced(to: 9))
        #expect(PathwayMitigation.outcome(score: 7, mode: .reduce, percent: 30) == .reduced(to: 4))
    }

    @Test func neverReducesAThreatToNothing() {
        #expect(PathwayMitigation.outcome(score: 12, mode: .reduce, percent: 100) == .reduced(to: 1))
        #expect(PathwayMitigation.outcome(score: 1, mode: .reduce, percent: 99) == .reduced(to: 1))
    }

    @Test func leavesAScoreAloneAtNoReduction() {
        #expect(PathwayMitigation.outcome(score: 12, mode: .reduce, percent: 0) == .reduced(to: 12))
    }

    @Test func floorsRatherThanRounds() {
        // 9 - 9 * 5 / 100 = 8.55, which floors to 8 and would round to 9.
        #expect(PathwayMitigation.outcome(score: 9, mode: .reduce, percent: 5) == .reduced(to: 8))
    }

    @Test func picksTheHighestOfManySensitivities() {
        #expect(SensitivityLadder.highest(of: []) == nil)
        #expect(SensitivityLadder.highest(of: [.publicData]) == .publicData)
        #expect(SensitivityLadder.highest(of: [.publicData, .restricted, .internalData]) == .restricted)
    }

    @Test func aModelStartsWithNoMitigationsSwitchedOn() {
        #expect(ThreatModel().pathwayMitigations == PathwayMitigationSettings())
    }
}

@Suite("Two mitigations answering one threat")
struct CombinedPathwayMitigationTests {
    @Test func compoundSoEachActsOnWhatTheOneBeforeItLeft() {
        // 12 × 0.5 = 6, then 6 × 0.75 = 4.5, which floors to 4.
        #expect(
            PathwayMitigation.combined(
                score: 12,
                by: [(mode: .reduce, percent: 50), (mode: .reduce, percent: 25)]
            ) == .reduced(to: 4)
        )
    }

    @Test func giveTheSameScoreInEitherOrder() {
        let oneWay = PathwayMitigation.combined(
            score: 12,
            by: [(mode: .reduce, percent: 50), (mode: .reduce, percent: 25)]
        )
        let otherWay = PathwayMitigation.combined(
            score: 12,
            by: [(mode: .reduce, percent: 25), (mode: .reduce, percent: 50)]
        )

        #expect(oneWay == otherWay)
    }

    @Test func lowerAScoreFurtherThanTheStrongerOneAlone() {
        let stronger = PathwayMitigation.outcome(score: 12, mode: .reduce, percent: 50)
        let both = PathwayMitigation.combined(
            score: 12,
            by: [(mode: .reduce, percent: 50), (mode: .reduce, percent: 25)]
        )

        #expect(stronger == .reduced(to: 6))
        #expect(both == .reduced(to: 4))
    }

    @Test func neverReachNothing() {
        #expect(
            PathwayMitigation.combined(
                score: 12,
                by: [(mode: .reduce, percent: 99), (mode: .reduce, percent: 99)]
            ) == .reduced(to: 1)
        )
    }

    @Test func removeTheThreatWhenAnyOneOfThemRemovesIt() {
        #expect(
            PathwayMitigation.combined(
                score: 12,
                by: [(mode: .reduce, percent: 10), (mode: .remove, percent: 0)]
            ) == .removed
        )
    }

    @Test func leaveAScoreAloneWhenNoneAnswersTheThreat() {
        #expect(PathwayMitigation.combined(score: 12, by: []) == .unchanged)
    }
}

@Suite("Where a mitigation's default mode and percentage come from")
struct PathwayMitigationDefaultsTests {
    private func definition(
        reducesRiskBy: Int? = nil,
        defaultMode: PathwayMitigationMode? = nil
    ) -> PathwayMitigationDefinition {
        PathwayMitigationDefinition(
            id: PathwayMitigationId("waf-protection"),
            label: "WAF Protection",
            description: "",
            mitigatesThreatIds: [ThreatId("credential-theft")],
            technologyIds: [TechnologyId("aws-waf")],
            reducesRiskBy: reducesRiskBy,
            defaultMode: defaultMode
        )
    }

    @Test func takesBothFromTheCatalogue() {
        let config = PathwayMitigationSettings()
            .config(for: definition(reducesRiskBy: 80, defaultMode: .remove))

        #expect(config.mode == .remove)
        #expect(config.reductionPercent == 80)
    }

    @Test func takesTheApplicationsOwnDefaultOnlyForWhatTheCatalogueLeavesOut() {
        let config = PathwayMitigationSettings().config(for: definition(reducesRiskBy: 80))

        #expect(config.mode == PathwayMitigationSettings.defaultConfig.mode)
        #expect(config.reductionPercent == 80)
    }

    @Test func letsTheUsersOwnSettingWinOverTheCatalogue() {
        let settings = PathwayMitigationSettings(
            configs: [
                PathwayMitigationId("waf-protection"):
                    PathwayMitigationConfig(isEnabled: true, mode: .reduce, reductionPercent: 10)
            ]
        )

        let config = settings.config(for: definition(reducesRiskBy: 80, defaultMode: .remove))
        #expect(config.mode == .reduce)
        #expect(config.reductionPercent == 10)
    }
}
