import Testing
import ThreatModelKit
import TestSupport

struct RemoveZoneTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 100, y: 100),
                    sensitivity: .internalData
                )
            ],
            zones: [
                Zone(id: ZoneId("z1"), rect: Rect(x: 0, y: 0, width: 400, height: 300)),
                Zone(id: ZoneId("z2"), rect: Rect(x: 500, y: 0, width: 400, height: 300))
            ]
        )
    )

    private func remove(_ id: String) -> RemoveZoneResponse {
        RemoveZone(models: models).execute(RemoveZoneRequest(zoneId: id))
    }

    @Test func removesTheNamedZoneAndLeavesTheOther() {
        #expect(remove("z1") == .removed)

        #expect(models.current().zones.map(\.id.value) == ["z2"])
    }

    @Test func leavesEveryComponentTheZoneHeld() {
        _ = remove("z1")

        #expect(models.current().components.map(\.id.value) == ["c1"])
        #expect(models.current().components.first?.position == Point(x: 100, y: 100))
    }

    @Test func refusesAZoneTheModelDoesNotHold() {
        #expect(remove("z9") == .unknownZone)
        #expect(models.current().zones.count == 2)
    }
}
