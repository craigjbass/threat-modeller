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
