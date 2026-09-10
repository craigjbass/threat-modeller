import Testing
import ThreatModelKit
import TestSupport

struct SetZonePropertiesTests {
    private let models = InMemoryThreatModelGateway(
        ThreatModel(zones: [
            Zone(id: ZoneId("z1"), rect: Rect(x: 0, y: 0, width: 400, height: 300))
        ])
    )

    private func set(
        _ id: String = "z1",
        name: String? = "Payments",
        networkZone: String = "private",
        networkType: String = "vpc",
        enabled: Bool = true,
        percent: Int = 40,
        boundary: String = "network"
    ) -> SetZonePropertiesResponse {
        SetZoneProperties(models: models).execute(
            SetZonePropertiesRequest(
                zoneId: id,
                name: name,
                networkZone: networkZone,
                networkType: networkType,
                riskReductionEnabled: enabled,
                riskReductionPercent: percent,
                boundary: boundary
            )
        )
    }

    private func zone() -> Zone? { models.current().zone(ZoneId("z1")) }

    @Test func setsEveryProperty() throws {
        #expect(set() == .updated)

        let changed = try #require(zone())
        #expect(changed.name == "Payments")
        #expect(changed.networkZone == .privateZone)
        #expect(changed.networkType == .vpc)
        #expect(changed.riskReductionEnabled)
        #expect(changed.riskReductionPercent == 40)
        #expect(changed.displayName == "Payments")
    }

    @Test func keepsTheRectangle() throws {
        _ = set()

        #expect(try #require(zone()).rect == Rect(x: 0, y: 0, width: 400, height: 300))
    }

    @Test func treatsAnEmptyNameAsNoName() throws {
        #expect(set(name: "   ") == .updated)

        #expect(try #require(zone()).name == nil)
        #expect(try #require(zone()).displayName == "VPC")
    }

    @Test func trimsTheNameItIsGiven() throws {
        _ = set(name: "  Payments  ")

        #expect(try #require(zone()).name == "Payments")
    }

    @Test func refusesAZoneTheModelDoesNotHold() {
        #expect(set("z9") == .unknownZone)
        #expect(zone()?.name == nil)
    }

    @Test func refusesAZoneKindItDoesNotKnow() {
        #expect(set(networkZone: "semi-private") == .unknownNetworkZone)
        #expect(zone()?.name == nil)
    }

    @Test func refusesANetworkTypeItDoesNotKnow() {
        #expect(set(networkType: "mainframe") == .unknownNetworkType)
        #expect(zone()?.name == nil)
    }

    @Test func refusesAReductionOutsideZeroToOneHundred() {
        #expect(set(percent: -1) == .reductionOutOfRange)
        #expect(set(percent: 101) == .reductionOutOfRange)
        #expect(zone()?.name == nil)
    }

    @Test func acceptsBothEndsOfTheReductionRange() {
        #expect(set(percent: 0) == .updated)
        #expect(set(percent: 100) == .updated)
        #expect(zone()?.riskReductionPercent == 100)
    }

    @Test func setsTheBoundary() throws {
        #expect(set(boundary: "privilege") == .updated)

        #expect(try #require(zone()).boundary == .privilege)
    }

    @Test func refusesABoundaryItDoesNotKnow() {
        #expect(set(boundary: "physical") == .unknownBoundary)
        #expect(zone()?.name == nil)
    }
}
