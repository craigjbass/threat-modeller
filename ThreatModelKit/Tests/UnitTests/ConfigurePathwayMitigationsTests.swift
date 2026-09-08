import Testing
import ThreatModelKit
import TestSupport

struct ConfigurePathwayMitigationsTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()
    private let waf = PathwayMitigationId("waf-protection")

    private func configure(
        master: Bool = true,
        id: String? = nil,
        enabled: Bool = true,
        mode: String = "reduce",
        percent: Int = 50
    ) -> ConfigurePathwayMitigationsResponse {
        ConfigurePathwayMitigations(models: models, catalogue: catalogue).execute(
            ConfigurePathwayMitigationsRequest(
                isMasterEnabled: master,
                mitigationId: id,
                isEnabled: enabled,
                mode: mode,
                reductionPercent: percent
            )
        )
    }

    private func settings() -> PathwayMitigationSettings {
        models.current().pathwayMitigations
    }

    @Test func turnsTheMasterToggleOnWithoutTouchingAMitigation() {
        #expect(configure(master: true, id: nil) == .configured)

        #expect(settings().isMasterEnabled)
        #expect(settings().configs.isEmpty)
    }

    @Test func setsOneMitigation() {
        #expect(configure(id: "waf-protection", enabled: false, mode: "remove", percent: 80) == .configured)

        #expect(settings().isMasterEnabled)
        #expect(settings().config(for: waf)
                == PathwayMitigationConfig(isEnabled: false, mode: .remove, reductionPercent: 80))
    }

    @Test func leavesEveryOtherMitigationAlone() {
        _ = configure(id: "waf-protection", mode: "remove")

        #expect(settings().configs.count == 1)
    }

    @Test func refusesAMitigationTheCatalogueDoesNotDefine() {
        #expect(configure(id: "magic-shield") == .unknownMitigation)
        #expect(settings().configs.isEmpty)
        #expect(settings().isMasterEnabled == false)
    }

    @Test func refusesAModeItDoesNotKnow() {
        #expect(configure(id: "waf-protection", mode: "obliterate") == .unknownMode)
        #expect(settings().configs.isEmpty)
    }

    @Test func refusesAReductionOutsideZeroToOneHundred() {
        #expect(configure(id: "waf-protection", percent: -1) == .reductionOutOfRange)
        #expect(configure(id: "waf-protection", percent: 101) == .reductionOutOfRange)
        #expect(settings().configs.isEmpty)
    }

    @Test func turnsTheMasterToggleBackOff() {
        _ = configure(master: true, id: "waf-protection")

        #expect(configure(master: false, id: nil) == .configured)
        #expect(settings().isMasterEnabled == false)
        // The per-mitigation settings survive, so turning the master back on
        // restores what the user had.
        #expect(settings().configs.count == 1)
    }
}
