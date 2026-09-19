import ArchitectureDSL
import FileGateways
import Testing
import ThreatModelKit
import TestSupport

/// Zones overlap, so which one draws over which is the person's decision, and
/// it survives a save.
@Suite("The order the zones draw in")
struct ZoneDrawingOrderTests {
    private func gateway() -> InMemoryThreatModelGateway {
        InMemoryThreatModelGateway(
            ThreatModel(zones: [
                Zone(id: ZoneId("back"), rect: Rect(x: 0, y: 0, width: 400, height: 300), name: "Back"),
                Zone(id: ZoneId("middle"), rect: Rect(x: 20, y: 20, width: 300, height: 200), name: "Middle"),
                Zone(id: ZoneId("front"), rect: Rect(x: 40, y: 40, width: 200, height: 150), name: "Front")
            ])
        )
    }

    private func order(_ models: InMemoryThreatModelGateway) -> [String] {
        models.current().zones.map(\.id.value)
    }

    @Test func movesEveryNamedZoneAndKeepsEachSize() {
        let models = gateway()

        let response = MoveZones(models: models).execute(
            MoveZonesRequest(moves: [
                ZoneMove(zoneId: "back", x: 100, y: 100),
                ZoneMove(zoneId: "front", x: 500, y: 20)
            ])
        )

        #expect(response == .moved(count: 2))
        #expect(models.current().zone(ZoneId("back"))?.rect
            == Rect(x: 100, y: 100, width: 400, height: 300))
        #expect(models.current().zone(ZoneId("front"))?.rect
            == Rect(x: 500, y: 20, width: 200, height: 150))
        #expect(models.current().zone(ZoneId("middle"))?.rect
            == Rect(x: 20, y: 20, width: 300, height: 200))
    }

    @Test func movesManyZonesAsOneChange() {
        let models = gateway()

        _ = MoveZones(models: models).execute(
            MoveZonesRequest(moves: [
                ZoneMove(zoneId: "back", x: 100, y: 100),
                ZoneMove(zoneId: "front", x: 500, y: 20)
            ])
        )
        _ = models.undo()

        #expect(models.current().zone(ZoneId("back"))?.rect
            == Rect(x: 0, y: 0, width: 400, height: 300))
        #expect(models.current().zone(ZoneId("front"))?.rect
            == Rect(x: 40, y: 40, width: 200, height: 150))
    }

    @Test func onDoubtAboutOneZoneItMovesNone() {
        let models = gateway()

        let response = MoveZones(models: models).execute(
            MoveZonesRequest(moves: [
                ZoneMove(zoneId: "back", x: 100, y: 100),
                ZoneMove(zoneId: "ghost", x: 0, y: 0)
            ])
        )

        #expect(response == .unknownZone(zoneId: "ghost"))
        #expect(models.current().zone(ZoneId("back"))?.rect
            == Rect(x: 0, y: 0, width: 400, height: 300))
    }

    @Test func takesTheLastPositionWhenAZoneIsNamedTwice() {
        let models = gateway()

        let response = MoveZones(models: models).execute(
            MoveZonesRequest(moves: [
                ZoneMove(zoneId: "back", x: 10, y: 20),
                ZoneMove(zoneId: "back", x: 30, y: 40)
            ])
        )

        #expect(response == .moved(count: 1))
        #expect(models.current().zone(ZoneId("back"))?.rect
            == Rect(x: 30, y: 40, width: 400, height: 300))
    }

    @Test func givesTheSameResultWhenCalledTwice() {
        let models = gateway()
        let request = MoveZonesRequest(moves: [ZoneMove(zoneId: "back", x: 55, y: 65)])

        _ = MoveZones(models: models).execute(request)
        _ = MoveZones(models: models).execute(request)

        #expect(models.current().zone(ZoneId("back"))?.rect
            == Rect(x: 55, y: 65, width: 400, height: 300))
    }

    @Test func bringsAZoneToTheFrontOfTheDrawingOrder() {
        let models = gateway()

        let response = ReorderZones(models: models).execute(
            ReorderZonesRequest(zoneIds: ["back"], placement: .front)
        )

        #expect(response == .reordered(zoneIds: ["middle", "front", "back"]))
        #expect(order(models) == ["middle", "front", "back"])
    }

    @Test func sendsAZoneToTheBackOfTheDrawingOrder() {
        let models = gateway()

        _ = ReorderZones(models: models).execute(
            ReorderZonesRequest(zoneIds: ["front"], placement: .back)
        )

        #expect(order(models) == ["front", "back", "middle"])
    }

    @Test func zonesMovedTogetherKeepTheirOrderAmongThemselves() {
        let models = gateway()

        _ = ReorderZones(models: models).execute(
            ReorderZonesRequest(zoneIds: ["back", "middle"], placement: .front)
        )

        #expect(order(models) == ["front", "back", "middle"])
    }

    @Test func oneUndoTakesTheWholeReorderBack() {
        let models = gateway()

        _ = ReorderZones(models: models).execute(
            ReorderZonesRequest(zoneIds: ["back", "middle"], placement: .front)
        )
        _ = models.undo()

        #expect(order(models) == ["back", "middle", "front"])
    }

    @Test func aDocumentRoundTripKeepsTheDrawingOrder() throws {
        let models = gateway()
        _ = ReorderZones(models: models).execute(
            ReorderZonesRequest(zoneIds: ["back"], placement: .front)
        )

        let data = try ThreatModelCodec().encode(models.current())
        let read = try ThreatModelCodec().decode(data)

        #expect(read.zones.map(\.id.value) == ["middle", "front", "back"])
    }

    /// The architecture file writes the zones in the order the model holds
    /// them, and reading it back gives that same order, so the order a person
    /// sets is the order the next open draws.
    @Test func anArchitectureFileRoundTripKeepsTheDrawingOrder() throws {
        let models = gateway()
        _ = ReorderZones(models: models).execute(
            ReorderZonesRequest(zoneIds: ["back"], placement: .front)
        )

        let text = ExportArchitecture(
            models: models,
            sources: HclArchitectureSource()
        ).execute(ExportArchitectureRequest()).text

        let source = try #require(HclArchitectureSource().read(text).source)
        #expect(source.zones.map(\.id) == ["middle", "front", "back"])
    }
}
