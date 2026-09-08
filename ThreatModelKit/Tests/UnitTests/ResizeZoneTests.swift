import Testing
import ThreatModelKit
import TestSupport

struct ResizeZoneTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(zones: [
            Zone(id: ZoneId("z1"), rect: Rect(x: 0, y: 0, width: 400, height: 300), name: "Payments"),
            Zone(id: ZoneId("z2"), rect: Rect(x: 500, y: 0, width: 400, height: 300))
        ])
    )

    private func resize(
        _ id: String,
        x: Double = 10,
        y: Double = 20,
        width: Double = 600,
        height: Double = 500
    ) -> ResizeZoneResponse {
        ResizeZone(models: models)
            .execute(ResizeZoneRequest(zoneId: id, x: x, y: y, width: width, height: height))
    }

    private func rect(_ id: String) -> Rect? {
        models.current().zone(ZoneId(id))?.rect
    }

    @Test func putsTheZoneAtTheNewRectangle() {
        #expect(resize("z1") == .resized)

        #expect(rect("z1") == Rect(x: 10, y: 20, width: 600, height: 500))
        #expect(rect("z2") == Rect(x: 500, y: 0, width: 400, height: 300))
    }

    @Test func movesAZoneWhenTheSizeIsUnchanged() {
        #expect(resize("z1", x: 300, y: 400, width: 400, height: 300) == .resized)

        #expect(rect("z1") == Rect(x: 300, y: 400, width: 400, height: 300))
    }

    @Test func keepsEveryOtherProperty() throws {
        _ = resize("z1")

        let zone = try #require(models.current().zone(ZoneId("z1")))
        #expect(zone.name == "Payments")
        #expect(zone.networkZone == .privateZone)
        #expect(zone.riskReductionPercent == 20)
    }

    @Test func keepsTheDrawingOrder() {
        _ = resize("z1")

        #expect(models.current().zones.map(\.id.value) == ["z1", "z2"])
    }

    @Test func refusesAZoneTheModelDoesNotHold() {
        #expect(resize("z9") == .unknownZone)
        #expect(rect("z1") == Rect(x: 0, y: 0, width: 400, height: 300))
    }

    @Test func refusesARectangleSmallerThanTheMinimum() {
        #expect(resize("z1", width: Zone.minimumSize.width - 1, height: 300) == .tooSmall)
        #expect(rect("z1") == Rect(x: 0, y: 0, width: 400, height: 300))
    }
}
