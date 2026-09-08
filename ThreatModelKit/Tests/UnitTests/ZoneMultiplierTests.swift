import Testing
import ThreatModelKit

struct ZoneMultiplierTests {
    private func zone(
        _ networkZone: NetworkZone = .privateZone,
        reduction: Int = 20,
        enabled: Bool = true
    ) -> Zone {
        Zone(
            id: ZoneId("z1"),
            rect: Rect(x: 0, y: 0, width: 400, height: 300),
            networkZone: networkZone,
            riskReductionEnabled: enabled,
            riskReductionPercent: reduction
        )
    }

    @Test func leavesAScoreAloneOutsideEveryZone() {
        #expect(ZoneMultiplier.value(for: nil) == 1.0)
    }

    @Test func leavesAScoreAloneInAPublicZone() {
        #expect(ZoneMultiplier.value(for: zone(.publicZone)) == 1.0)
    }

    @Test func leavesAScoreAloneInAPrivateZoneWithReductionOff() {
        #expect(ZoneMultiplier.value(for: zone(reduction: 50, enabled: false)) == 1.0)
    }

    @Test func reducesAScoreInAPrivateZone() {
        #expect(ZoneMultiplier.value(for: zone(reduction: 20)) == 0.8)
        #expect(ZoneMultiplier.value(for: zone(reduction: 50)) == 0.5)
        #expect(ZoneMultiplier.value(for: zone(reduction: 0)) == 1.0)
        #expect(ZoneMultiplier.value(for: zone(reduction: 100)) == 0.0)
    }

    @Test func roundsTheReducedScore() {
        #expect(ZoneMultiplier.apply(0.8, to: 12) == 10)   // 9.6 rounds to 10
        #expect(ZoneMultiplier.apply(0.8, to: 3) == 2)     // 2.4 rounds to 2
        #expect(ZoneMultiplier.apply(0.5, to: 5) == 3)     // 2.5 rounds away from zero
        #expect(ZoneMultiplier.apply(1.0, to: 7) == 7)
    }

    @Test func leavesALinkAloneUnlessBothEndsAreInPrivateZones() {
        #expect(ZoneMultiplier.valueForConnection(sourceZone: nil, targetZone: zone()) == 1.0)
        #expect(ZoneMultiplier.valueForConnection(sourceZone: zone(), targetZone: nil) == 1.0)
        #expect(ZoneMultiplier.valueForConnection(sourceZone: zone(.publicZone), targetZone: zone()) == 1.0)
    }

    @Test func givesALinkTheLowerOfTheTwoReductions() {
        let gentle = zone(reduction: 10)
        let strong = zone(reduction: 60)

        // 10 per cent is the lower reduction, so the multiplier is 0.9.
        #expect(ZoneMultiplier.valueForConnection(sourceZone: gentle, targetZone: strong) == 0.9)
        #expect(ZoneMultiplier.valueForConnection(sourceZone: strong, targetZone: gentle) == 0.9)
    }

    @Test func treatsAnEndWithReductionOffAsNoReductionForTheLink() {
        let off = zone(reduction: 90, enabled: false)
        let strong = zone(reduction: 60)

        #expect(ZoneMultiplier.valueForConnection(sourceZone: off, targetZone: strong) == 1.0)
    }
}
