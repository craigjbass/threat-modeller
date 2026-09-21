import Testing
import ThreatModelKit
import TestSupport

struct ViewThreatModelTests {
    private let catalogue = CatalogueFixture.catalogue()

    /// A hand-built model states a picture and no membership, so the
    /// membership that picture means is filled in, the way an older document
    /// is read.
    private func view(_ model: ThreatModel) -> ViewThreatModelResponse {
        ViewThreatModel(
            models: InMemoryThreatModelGateway(model.withZoneMembershipFromGeometry()),
            catalogue: catalogue
        )
        .execute(ViewThreatModelRequest())
    }

    private func component(
        _ id: String,
        technologyId: String = "aws-ec2",
        x: Double = 0,
        y: Double = 0,
        customName: String? = nil,
        threatsDisabled: Bool = false
    ) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId(technologyId),
            position: Point(x: x, y: y),
            sensitivity: .confidential,
            customName: customName,
            threatsDisabled: threatsDisabled
        )
    }

    @Test func showsAnEmptyModel() {
        let response = view(ThreatModel())

        #expect(response.name == "Untitled")
        #expect(response.components.isEmpty)
        #expect(response.connections.isEmpty)
    }

    @Test func describesAComponentForDrawing() throws {
        let response = view(ThreatModel(components: [component("c1", x: 120, y: 40)]))

        let drawn = try #require(response.components.first)
        #expect(drawn.id == "c1")
        #expect(drawn.technologyId == "aws-ec2")
        #expect(drawn.name == "EC2")
        #expect(drawn.providerId == "aws")
        #expect(drawn.categoryId == "compute")
        #expect(drawn.x == 120)
        #expect(drawn.y == 40)
        #expect(drawn.sensitivityId == "confidential")
        #expect(drawn.threatsDisabled == false)
        #expect(drawn.isUnknownTechnology == false)
    }

    @Test func prefersTheUsersOwnNameForAComponent() throws {
        let response = view(ThreatModel(components: [component("c1", customName: "Web tier")]))

        #expect(try #require(response.components.first).name == "Web tier")
    }

    @Test func stillDrawsAComponentWhoseTechnologyLeftTheCatalogue() throws {
        let response = view(ThreatModel(components: [component("c1", technologyId: "aws-retired")]))

        let drawn = try #require(response.components.first)
        #expect(drawn.name == "aws-retired")
        #expect(drawn.providerId == "")
        #expect(drawn.categoryId == "")
        #expect(drawn.isUnknownTechnology)
    }

    @Test func listsConnectionsInModelOrder() {
        let response = view(
            ThreatModel(
                components: [component("c1"), component("c2"), component("c3")],
                connections: [
                    Connection(id: ConnectionId("k2"), source: ComponentId("c2"), target: ComponentId("c3")),
                    Connection(id: ConnectionId("k1"), source: ComponentId("c1"), target: ComponentId("c2"))
                ]
            )
        )

        #expect(response.connections.map(\.id) == ["k2", "k1"])
        #expect(response.connections.first?.sourceComponentId == "c2")
        #expect(response.connections.first?.targetComponentId == "c3")
    }

    private func zone(
        _ id: String,
        x: Double = 0,
        y: Double = 0,
        name: String? = nil,
        networkZone: NetworkZone = .privateZone
    ) -> Zone {
        Zone(
            id: ZoneId(id),
            rect: Rect(x: x, y: y, width: 400, height: 300),
            name: name,
            networkZone: networkZone,
            networkType: .vpc,
            riskReductionEnabled: true,
            riskReductionPercent: 35
        )
    }

    @Test func describesAZoneForDrawing() throws {
        let response = view(ThreatModel(zones: [zone("z1", x: 20, y: 30, name: "Payments")]))

        let drawn = try #require(response.zones.first)
        #expect(drawn.id == "z1")
        #expect(drawn.name == "Payments")
        #expect(drawn.customName == "Payments")
        #expect(drawn.networkZoneId == "private")
        #expect(drawn.networkTypeId == "vpc")
        #expect(drawn.riskReductionEnabled)
        #expect(drawn.riskReductionPercent == 35)
        #expect(drawn.x == 20)
        #expect(drawn.y == 30)
        #expect(drawn.width == 400)
        #expect(drawn.height == 300)
    }

    @Test func showsTheFallbackNameForAZoneWithoutOne() throws {
        let response = view(ThreatModel(zones: [zone("z1")]))

        let drawn = try #require(response.zones.first)
        #expect(drawn.name == "VPC")
        #expect(drawn.customName == nil)
    }

    @Test func listsZonesInDrawingOrder() {
        let response = view(ThreatModel(zones: [zone("z1"), zone("z2", x: 500)]))

        #expect(response.zones.map(\.id) == ["z1", "z2"])
    }

    @Test func tellsTheCanvasWhichZoneHoldsAComponent() throws {
        // The component sits at 100,100 and its centre is 80 by 36 further on,
        // so it is inside the zone rectangle below the 40 point header.
        let response = view(
            ThreatModel(components: [component("c1", x: 100, y: 100)], zones: [zone("z1")])
        )

        #expect(try #require(response.components.first).zoneId == "z1")
    }

    @Test func reportsNoZoneForAComponentOutsideEveryZone() throws {
        let response = view(
            ThreatModel(components: [component("c1", x: 900, y: 900)], zones: [zone("z1")])
        )

        #expect(try #require(response.components.first).zoneId == nil)
    }

    @Test func givesAComponentTheLaterOfTwoOverlappingZones() throws {
        let response = view(
            ThreatModel(
                components: [component("c1", x: 100, y: 100)],
                zones: [zone("z1"), zone("z2")]
            )
        )

        #expect(try #require(response.components.first).zoneId == "z2")
    }

    // MARK: what the interface needs and could not see

    /// The assumptions and the mitigates edges are model state a person
    /// writes, so the read that draws the model shows them.
    @Test func showsWhatTheSystemTakesOnTrust() {
        let response = view(
            ThreatModel(
                assumptions: [
                    SystemAssumption(label: "network-segmented", text: "It is.", owner: "platform")
                ]
            )
        )

        #expect(response.assumptions.count == 1)
        #expect(response.assumptions.first?.label == "network-segmented")
        #expect(response.assumptions.first?.text == "It is.")
        #expect(response.assumptions.first?.owner == "platform")
    }

    @Test func showsWhatOneComponentLowersOnAnother() {
        let response = view(
            ThreatModel(
                components: [component("guard"), component("store")],
                mitigatesEdges: [
                    MitigatesEdge(
                        source: ComponentId("guard"),
                        target: ComponentId("store"),
                        threatIds: [ThreatId("credential-theft")],
                        status: .proposed
                    )
                ]
            )
        )

        #expect(response.mitigations.count == 1)
        #expect(response.mitigations.first?.sourceComponentId == "guard")
        #expect(response.mitigations.first?.targetComponentId == "store")
        #expect(response.mitigations.first?.threatIds == ["credential-theft"])
        #expect(response.mitigations.first?.status == "proposed")
    }

    @Test func showsNeitherForAModelThatHoldsNone() {
        let response = view(ThreatModel())

        #expect(response.assumptions.isEmpty)
        #expect(response.mitigations.isEmpty)
    }
}
