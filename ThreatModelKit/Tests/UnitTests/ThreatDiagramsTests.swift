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

    // MARK: which element the picture calls out

    @Test func marksTheOneElementTheThreatIsOn() throws {
        let focused = try #require(ThreatDiagrams.focus(model, on: "component:b"))

        #expect(focused.focus == "component:b")
        #expect(focused.isFocused("component:b"))
        #expect(focused.strength(of: "component:b") == 1)
        #expect(focused.strength(of: "component:a") < 1)
    }

    @Test func everythingDrawsAtFullStrengthWithNoFocus() {
        #expect(model.focus == nil)
        #expect(model.strength(of: "component:a") == 1)
        #expect(model.isFocused("component:a") == false)
    }

    @Test func theCalledOutNodeDrawsHeavierThanTheRest() throws {
        let focused = try #require(ThreatDiagrams.focus(model, on: "component:b"))
        let widths = DiagramBuilder.drawing(of: focused).shapes.compactMap { shape -> Double? in
            if case .ellipse(_, let style) = shape { return style.width }
            if case .rectangle(_, _, let style) = shape { return style.width }
            return nil
        }

        #expect(widths.contains(DiagramBuilder.focusWidth))
    }

    @Test func theCalledOutFlowDrawsHeavierThanTheRest() throws {
        let focused = try #require(ThreatDiagrams.focus(model, on: "connection:a-b"))
        let widths = DiagramBuilder.drawing(of: focused).shapes.compactMap { shape -> Double? in
            guard case .path(_, let style) = shape else { return nil }
            return style.width
        }

        #expect(widths.contains(DiagramBuilder.focusWidth))
    }

    @Test func thePictureNamesWhatItCallsOut() throws {
        let focused = try #require(
            ThreatDiagrams.focus(model, on: "component:b", titled: "b — Spoofing")
        )
        let texts = DiagramBuilder.drawing(of: focused).shapes.compactMap { shape -> String? in
            guard case .text(let text, _, _, _, _, _) = shape else { return nil }
            return text
        }

        #expect(texts.contains("b — Spoofing"))
    }

    @Test func theTitleSitsInsideThePicture() throws {
        let focused = try #require(
            ThreatDiagrams.focus(model, on: "component:b", titled: "b — Spoofing")
        )
        let drawing = DiagramBuilder.drawing(of: focused)
        let title = try #require(
            drawing.shapes.first { shape in
                if case .text(let text, _, _, _, _, _) = shape { return text == "b — Spoofing" }
                return false
            }
        )
        guard case .text(_, let at, _, _, _, _) = title else { return }

        #expect(at.y >= drawing.origin.y)
        #expect(at.x >= drawing.origin.x)
    }
}

@Suite("A fragment placed on its own")
struct FragmentLayoutTests {
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
            y: -500,
            width: 3000,
            height: 2000
        )
    }

    @Test func placesTheFragmentWhereAFragmentBelongs() {
        let placed = ThreatDiagrams.laidOut(
            DiagramBuilder.Model(
                components: [component("a", x: 5000, zoneId: "z")],
                connections: [],
                zones: [zone("z", x: 4000)]
            )
        )

        // Nothing keeps the place a layout of thirty-five nodes gave it.
        #expect(placed.components.first?.x ?? 0 < 400)
        #expect(placed.zones.first?.x ?? 0 < 400)
    }

    @Test func cutsAZoneToWhatTheFragmentHolds() {
        let placed = ThreatDiagrams.laidOut(
            DiagramBuilder.Model(
                components: [component("a", x: 0, zoneId: "z")],
                connections: [],
                zones: [zone("z", x: 0)]
            )
        )

        #expect(placed.zones.first?.width ?? 0 < 400)
        #expect(placed.zones.first?.height ?? 0 < 400)
    }

    @Test func keepsAComponentInsideItsZone() throws {
        let placed = ThreatDiagrams.laidOut(
            DiagramBuilder.Model(
                components: [component("a", x: 0, zoneId: "z"), component("b", x: 900, zoneId: "z")],
                connections: [],
                zones: [zone("z", x: 0)]
            )
        )

        let zone = try #require(placed.zones.first)
        let rect = Rect(x: zone.x, y: zone.y, width: zone.width, height: zone.height)
        for component in placed.components {
            let centre = Point(x: component.x + 80, y: component.y + 36)
            #expect(rect.insetFromTop(by: ZoneContainment.headerHeight).contains(centre))
        }
    }

    @Test func placesTheSameFragmentTheSameWayTwice() {
        let model = DiagramBuilder.Model(
            components: [component("a", x: 0, zoneId: "z"), component("b", x: 900, zoneId: nil)],
            connections: [ViewedConnection(id: "a-b", sourceComponentId: "a", targetComponentId: "b")],
            zones: [zone("z", x: 0)]
        )

        #expect(ThreatDiagrams.laidOut(model) == ThreatDiagrams.laidOut(model))
    }

    @Test func keepsAComponentWhoseZoneIsNotInTheFragment() {
        let placed = ThreatDiagrams.laidOut(
            DiagramBuilder.Model(
                components: [component("a", x: 0, zoneId: "gone")],
                connections: [],
                zones: []
            )
        )

        #expect(placed.components.map(\.id) == ["a"])
    }
}
