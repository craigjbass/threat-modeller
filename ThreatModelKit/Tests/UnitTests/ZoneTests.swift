import Testing
import ThreatModelKit

struct ZoneTests {
    private func zone(
        name: String? = nil,
        networkZone: NetworkZone = .privateZone,
        networkType: ZoneNetworkType = .generic
    ) -> Zone {
        Zone(
            id: ZoneId("z1"),
            rect: Rect(x: 0, y: 0, width: 400, height: 300),
            name: name,
            networkZone: networkZone,
            networkType: networkType
        )
    }

    @Test func prefersTheUsersOwnName() {
        #expect(zone(name: "Payments VPC", networkType: .vpc).displayName == "Payments VPC")
    }

    @Test func fallsBackToTheNetworkTypeLabel() {
        #expect(zone(networkType: .vpc).displayName == "VPC")
        #expect(zone(networkType: .onPremises).displayName == "On-Premises")
    }

    @Test func fallsBackToTheZoneLabelForAGenericNetwork() {
        #expect(zone(networkZone: .privateZone, networkType: .generic).displayName == "Private Zone")
        #expect(zone(networkZone: .publicZone, networkType: .generic).displayName == "Public Zone")
    }

    @Test func treatsAnEmptyNameAsNoName() {
        #expect(zone(name: "", networkType: .vpc).displayName == "VPC")
        #expect(zone(name: "   ", networkType: .vpc).displayName == "VPC")
    }

    @Test func defaultsToAPrivateGenericZoneThatReducesRisk() {
        let plain = Zone(id: ZoneId("z1"), rect: Rect(x: 0, y: 0, width: 400, height: 300))

        #expect(plain.networkZone == .privateZone)
        #expect(plain.networkType == .generic)
        #expect(plain.riskReductionEnabled)
        #expect(plain.riskReductionPercent == Zone.defaultRiskReductionPercent)
        #expect(Zone.defaultRiskReductionPercent == 20)
    }

    @Test func namesEveryValueTheUserCanChoose() {
        #expect(NetworkZone.allCases.map(\.rawValue) == ["public", "private"])
        #expect(ZoneNetworkType.allCases.map(\.rawValue) == [
            "generic", "vpc", "subnet", "on-premises", "dmz", "management", "data"
        ])
        #expect(ZoneNetworkType.allCases.allSatisfy { $0.label.isEmpty == false })
    }

    @Test func findsTheCentreOfAComponentsFootprint() {
        let component = Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 100, y: 200),
            sensitivity: .internalData
        )

        #expect(component.centre == Point(
            x: 100 + Component.size.width / 2,
            y: 200 + Component.size.height / 2
        ))
    }

    @Test func findsAZoneById() {
        let model = ThreatModel(zones: [zone()])

        #expect(model.zone(ZoneId("z1"))?.id == ZoneId("z1"))
        #expect(model.zone(ZoneId("z9")) == nil)
    }
}
