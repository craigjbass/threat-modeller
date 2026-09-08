import Testing
import ThreatModelKit
import TestSupport

struct AddZoneTests {
    private let models = InMemoryThreatModelGateway()
    private let ids = SequentialIdentityGenerator()

    private func add(x: Double = 0, y: Double = 0, width: Double = 400, height: Double = 300) -> AddZoneResponse {
        AddZone(models: models, ids: ids)
            .execute(AddZoneRequest(x: x, y: y, width: width, height: height))
    }

    @Test func addsAZoneAtTheRectangleGiven() throws {
        #expect(add(x: 40, y: 60, width: 500, height: 400) == .added(zoneId: "id-1"))

        let zone = try #require(models.current().zones.first)
        #expect(zone.rect == Rect(x: 40, y: 60, width: 500, height: 400))
    }

    @Test func startsAZonePrivateGenericAndReducingRisk() throws {
        _ = add()

        let zone = try #require(models.current().zones.first)
        #expect(zone.name == nil)
        #expect(zone.networkZone == .privateZone)
        #expect(zone.networkType == .generic)
        #expect(zone.riskReductionEnabled)
        #expect(zone.riskReductionPercent == 20)
        #expect(zone.displayName == "Private Zone")
    }

    @Test func keepsZonesInDrawingOrder() {
        _ = add()
        _ = add(x: 100, y: 100)

        #expect(models.current().zones.map(\.id.value) == ["id-1", "id-2"])
    }

    @Test func refusesARectangleSmallerThanTheMinimum() {
        #expect(add(width: Zone.minimumSize.width - 1, height: 300) == .tooSmall)
        #expect(add(width: 400, height: Zone.minimumSize.height - 1) == .tooSmall)
        #expect(models.current().zones.isEmpty)
    }

    @Test func acceptsARectangleExactlyTheMinimum() {
        #expect(add(width: Zone.minimumSize.width, height: Zone.minimumSize.height)
                == .added(zoneId: "id-1"))
    }

    @Test func spendsNoIdentifierOnAZoneItRefuses() {
        _ = add(width: 10, height: 10)

        #expect(add() == .added(zoneId: "id-1"))
    }
}
