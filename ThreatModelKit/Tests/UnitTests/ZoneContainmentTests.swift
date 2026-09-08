import Testing
import ThreatModelKit

struct ZoneContainmentTests {
    private func zone(_ id: String, x: Double, y: Double, width: Double = 400, height: Double = 300) -> Zone {
        Zone(id: ZoneId(id), rect: Rect(x: x, y: y, width: width, height: height))
    }

    @Test func holdsAPointBelowTheHeaderBand() {
        let zones = [zone("z1", x: 0, y: 0)]

        #expect(ZoneContainment.zone(holding: Point(x: 200, y: 150), in: zones)?.id == ZoneId("z1"))
    }

    @Test func ignoresAPointInsideTheHeaderBand() {
        let zones = [zone("z1", x: 0, y: 0)]

        #expect(ZoneContainment.headerHeight == 40)
        #expect(ZoneContainment.zone(holding: Point(x: 200, y: 39), in: zones) == nil)
        #expect(ZoneContainment.zone(holding: Point(x: 200, y: 40), in: zones)?.id == ZoneId("z1"))
    }

    @Test func ignoresAPointOutsideEveryZone() {
        #expect(ZoneContainment.zone(holding: Point(x: 900, y: 900), in: [zone("z1", x: 0, y: 0)]) == nil)
    }

    @Test func holdsNothingWhenThereAreNoZones() {
        #expect(ZoneContainment.zone(holding: Point(x: 10, y: 10), in: []) == nil)
    }

    @Test func givesTheLaterZoneThePointWhenTwoOverlap() {
        let zones = [zone("z1", x: 0, y: 0), zone("z2", x: 100, y: 100)]

        #expect(ZoneContainment.zone(holding: Point(x: 200, y: 200), in: zones)?.id == ZoneId("z2"))
    }

    @Test func fallsBackToTheEarlierZoneOutsideTheLaterOne() {
        let zones = [zone("z1", x: 0, y: 0), zone("z2", x: 100, y: 100)]

        #expect(ZoneContainment.zone(holding: Point(x: 50, y: 50), in: zones)?.id == ZoneId("z1"))
    }

    @Test func holdsNothingInsideAZoneShorterThanItsHeader() {
        let squashed = Zone(id: ZoneId("z1"), rect: Rect(x: 0, y: 0, width: 400, height: 20))

        #expect(ZoneContainment.zone(holding: Point(x: 200, y: 10), in: [squashed]) == nil)
    }
}
