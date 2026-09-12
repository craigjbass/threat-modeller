import Foundation
import Testing
import DiagramRendering
import ThreatModelKit

@Suite("A picture of one threat")
struct ThreatDiagramsTests {
    private func component(_ id: String, x: Double, zoneId: String?) -> ViewedComponent {
        ViewedComponent(
            id: id,
            technologyId: "aws-ec2",
            name: id,
            customName: nil,
            providerId: "aws",
            categoryId: "compute",
            x: x,
            y: 0,
            sensitivityId: "internal",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: zoneId
        )
    }

    private func zone(_ id: String, x: Double) -> ViewedZone {
        ViewedZone(
            id: id,
            name: id,
            customName: nil,
            networkZoneId: "private",
            networkTypeId: "generic",
            riskReductionEnabled: true,
            riskReductionPercent: 20,
            x: x,
            y: -60,
            width: 400,
            height: 300
        )
    }

    private var model: DiagramBuilder.Model {
        DiagramBuilder.Model(
            components: [
                component("a", x: 0, zoneId: "left"),
                component("b", x: 500, zoneId: "right"),
                component("c", x: 1000, zoneId: "right"),
                component("far", x: 2000, zoneId: nil)
            ],
            connections: [
                ViewedConnection(id: "a-b", sourceComponentId: "a", targetComponentId: "b"),
                ViewedConnection(id: "b-c", sourceComponentId: "b", targetComponentId: "c")
            ],
            zones: [zone("left", x: -40), zone("right", x: 460)]
        )
    }

    @Test func drawsAComponentAndEverythingOneHopFromIt() throws {
        let focused = try #require(ThreatDiagrams.focus(model, on: "component:b"))

        #expect(Set(focused.components.map(\.id)) == ["a", "b", "c"])
        #expect(Set(focused.connections.map(\.id)) == ["a-b", "b-c"])
        #expect(Set(focused.zones.map(\.id)) == ["left", "right"])
    }

    @Test func drawsAFlowAndItsTwoEnds() throws {
        let focused = try #require(ThreatDiagrams.focus(model, on: "connection:a-b"))

        #expect(Set(focused.components.map(\.id)) == ["a", "b"])
        #expect(focused.connections.map(\.id) == ["a-b"])
    }

    @Test func drawsAZoneWhatItHoldsAndWhatCrossesItsEdge() throws {
        let focused = try #require(ThreatDiagrams.focus(model, on: "zone:left"))

        // "a" is inside it, and "b" is at the other end of the flow leaving it.
        #expect(Set(focused.components.map(\.id)) == ["a", "b"])
        #expect(focused.connections.map(\.id) == ["a-b"])
    }

    @Test func leavesOutWhatTheThreatIsNotAbout() throws {
        let focused = try #require(ThreatDiagrams.focus(model, on: "component:a"))

        #expect(focused.components.contains { $0.id == "far" } == false)
        #expect(focused.components.contains { $0.id == "c" } == false)
    }

    @Test func saysNothingForASourceTheModelDoesNotHold() {
        #expect(ThreatDiagrams.focus(model, on: "component:missing") == nil)
        #expect(ThreatDiagrams.focus(model, on: "nonsense") == nil)
    }

    @Test func namesEachPictureAfterItsPlaceInTheList() {
        let threats = [
            reportThreat(threatId: "t1", sourceId: "component:a"),
            reportThreat(threatId: "t2", sourceId: "connection:a-b")
        ]
        let pictures = ThreatDiagrams.pictures(of: model, for: threats, stem: "payments")

        #expect(pictures.map(\.fileName) == ["payments-threat-1.svg", "payments-threat-2.svg"])
        #expect(pictures[0].key == "t1@component:a")
        #expect(pictures.allSatisfy { $0.svg.hasPrefix("<svg") })
    }

    @Test func drawsNoPictureForAThreatOnSomethingTheModelDoesNotHold() {
        let pictures = ThreatDiagrams.pictures(
            of: model,
            for: [reportThreat(threatId: "t1", sourceId: "component:gone")],
            stem: "payments"
        )

        #expect(pictures.isEmpty)
    }

    private func reportThreat(threatId: String, sourceId: String) -> ReportThreat {
        ReportThreat(
            threatId: threatId,
            name: threatId,
            description: "",
            severityLabel: "High",
            riskScore: 9,
            riskLevel: "high",
            strideLabels: [],
            mitreTechniqueIds: [],
            sourceName: sourceId,
            sourceKind: "Component",
            sourceId: sourceId,
            controls: [],
            pathwayMitigationLabels: []
        )
    }
}

@Suite("A zone in a fragment")
struct FocusedZoneTests {
    private func component(_ id: String, x: Double, zoneId: String?) -> ViewedComponent {
        ViewedComponent(
            id: id,
            technologyId: "aws-ec2",
            name: id,
            customName: nil,
            providerId: "aws",
            categoryId: "compute",
            x: x,
            y: 0,
            sensitivityId: "internal",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: zoneId
        )
    }

    private let wide = ViewedZone(
        id: "z",
        name: "z",
        customName: nil,
        networkZoneId: "private",
        networkTypeId: "generic",
        riskReductionEnabled: true,
        riskReductionPercent: 20,
        x: -500,
        y: -500,
        width: 3000,
        height: 2000
    )

    @Test func cutsAZoneToWhatThePictureStillShows() {
        let model = DiagramBuilder.Model(
            components: [component("a", x: 0, zoneId: "z"), component("far", x: 2000, zoneId: "z")],
            connections: [],
            zones: [wide]
        )

        let focused = ThreatDiagrams.focus(model, on: "component:a")
        let zone = focused?.zones.first

        #expect(zone != nil)
        #expect((zone?.width ?? 0) < 400)
        #expect((zone?.height ?? 0) < 400)
    }

    @Test func keepsTheComponentInsideTheZoneItCutTo() {
        let model = DiagramBuilder.Model(
            components: [component("a", x: 0, zoneId: "z")],
            connections: [],
            zones: [wide]
        )

        let zone = ThreatDiagrams.focus(model, on: "component:a")?.zones.first
        let centre = Point(x: 0 + 80, y: 0 + 36)

        #expect(zone != nil)
        let rect = Rect(
            x: zone?.x ?? 0,
            y: zone?.y ?? 0,
            width: zone?.width ?? 0,
            height: zone?.height ?? 0
        )
        #expect(rect.insetFromTop(by: ZoneContainment.headerHeight).contains(centre))
    }

    @Test func leavesAZoneAloneWhenNothingIsLeftInIt() {
        let model = DiagramBuilder.Model(
            components: [component("a", x: 0, zoneId: nil)],
            connections: [],
            zones: [wide]
        )

        // Nothing in the picture belongs to the zone, so the zone is not shown.
        #expect(ThreatDiagrams.focus(model, on: "component:a")?.zones.isEmpty == true)
    }
}

@Suite("Taking the blank out of a fragment")
struct PackedFragmentTests {
    private func component(_ id: String, x: Double, y: Double = 0) -> ViewedComponent {
        ViewedComponent(
            id: id,
            technologyId: "aws-ec2",
            name: id,
            customName: nil,
            providerId: "aws",
            categoryId: "compute",
            x: x,
            y: y,
            sensitivityId: "internal",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: nil
        )
    }

    @Test func closesAWideBlankBetweenTwoThings() {
        let packed = ThreatDiagrams.packed(
            DiagramBuilder.Model(
                components: [component("a", x: 0), component("far", x: 3000)],
                connections: [],
                zones: []
            )
        )

        let places = packed.components.map(\.x).sorted()
        #expect(places[0] == 0)
        #expect(places[1] < 400)
    }

    @Test func leavesATightPairAlone() {
        let packed = ThreatDiagrams.packed(
            DiagramBuilder.Model(
                components: [component("a", x: 0), component("b", x: 220)],
                connections: [],
                zones: []
            )
        )

        #expect(packed.components.map(\.x).sorted() == [0, 220])
    }

    @Test func closesTheBlankOnBothAxes() {
        let packed = ThreatDiagrams.packed(
            DiagramBuilder.Model(
                components: [component("a", x: 0, y: 0), component("far", x: 2000, y: 2000)],
                connections: [],
                zones: []
            )
        )

        let far = packed.components.first { $0.id == "far" }
        #expect((far?.x ?? 0) < 400)
        #expect((far?.y ?? 0) < 400)
    }

    @Test func keepsTheOrderItFound() {
        let packed = ThreatDiagrams.packed(
            DiagramBuilder.Model(
                components: [
                    component("a", x: 0),
                    component("b", x: 1000),
                    component("c", x: 2000)
                ],
                connections: [],
                zones: []
            )
        )

        let byId = Dictionary(uniqueKeysWithValues: packed.components.map { ($0.id, $0.x) })
        #expect((byId["a"] ?? 0) < (byId["b"] ?? 0))
        #expect((byId["b"] ?? 0) < (byId["c"] ?? 0))
    }

    @Test func leavesOneThingWhereItIs() {
        let packed = ThreatDiagrams.packed(
            DiagramBuilder.Model(components: [component("a", x: 900)], connections: [], zones: [])
        )

        #expect(packed.components.first?.x == 900)
    }
}
