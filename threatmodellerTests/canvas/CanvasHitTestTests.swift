import CoreGraphics
import Testing
import ThreatModelKit
@testable import threatmodeller

struct CanvasHitTestTests {
    private func component(_ id: String, x: Double, y: Double) -> ViewedComponent {
        ViewedComponent(
            id: id,
            technologyId: "aws-ec2",
            name: "EC2",
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

    private func link(_ id: String, _ source: String, _ target: String) -> ViewedConnection {
        ViewedConnection(id: id, sourceComponentId: source, targetComponentId: target)
    }

    @Test func placesEachComponentAtItsOwnPosition() throws {
        let boxes = CanvasHitTest.boxes(
            for: [component("c1", x: 10, y: 20), component("c2", x: 300, y: 40)],
            selected: [],
            dragTranslation: .zero
        )

        #expect(boxes.count == 2)
        #expect(try #require(boxes["c1"]).origin == CGPoint(x: 10, y: 20))
        #expect(try #require(boxes["c2"]).origin == CGPoint(x: 300, y: 40))
    }

    @Test func shiftsOnlyTheSelectedComponentsByTheDragInFlight() throws {
        let boxes = CanvasHitTest.boxes(
            for: [component("c1", x: 10, y: 20), component("c2", x: 300, y: 40)],
            selected: ["c1"],
            dragTranslation: CGSize(width: 5, height: -7)
        )

        #expect(try #require(boxes["c1"]).origin == CGPoint(x: 15, y: 13))
        #expect(try #require(boxes["c2"]).origin == CGPoint(x: 300, y: 40))
    }

    @Test func findsTheComponentUnderAPoint() {
        let components = [component("c1", x: 0, y: 0), component("c2", x: 400, y: 0)]

        #expect(CanvasHitTest.component(under: CGPoint(x: 20, y: 20), components: components) == "c1")
        #expect(CanvasHitTest.component(under: CGPoint(x: 420, y: 20), components: components) == "c2")
        #expect(CanvasHitTest.component(under: CGPoint(x: 900, y: 900), components: components) == nil)
    }

    @Test func givesALaterComponentThePointWhenTwoOverlap() {
        let components = [component("c1", x: 0, y: 0), component("c2", x: 10, y: 10)]

        #expect(CanvasHitTest.component(under: CGPoint(x: 40, y: 40), components: components) == "c2")
    }

    @Test func findsTheLinkUnderAPoint() throws {
        let components = [component("c1", x: 0, y: 0), component("c2", x: 500, y: 0)]
        let boxes = CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero)
        let connections = [link("k1", "c1", "c2")]

        let path = try #require(CanvasHitTest.path(for: connections[0], boxes: boxes))
        let onTheCurve = path.point(at: 0.5)

        #expect(CanvasHitTest.connection(under: onTheCurve, connections: connections, boxes: boxes) == "k1")
        #expect(CanvasHitTest.connection(
            under: CGPoint(x: onTheCurve.x, y: onTheCurve.y + 200),
            connections: connections,
            boxes: boxes
        ) == nil)
    }

    @Test func findsNoLinkWhenAnEndIsMissing() {
        let boxes = CanvasHitTest.boxes(
            for: [component("c1", x: 0, y: 0)],
            selected: [],
            dragTranslation: .zero
        )

        #expect(CanvasHitTest.path(for: link("k1", "c1", "c9"), boxes: boxes) == nil)
        #expect(CanvasHitTest.connection(
            under: CGPoint(x: 100, y: 40),
            connections: [link("k1", "c1", "c9")],
            boxes: boxes
        ) == nil)
    }

    @Test func givesALaterLinkThePointWhenTwoRunTogether() throws {
        let components = [component("c1", x: 0, y: 0), component("c2", x: 500, y: 0)]
        let boxes = CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero)
        let connections = [link("k1", "c1", "c2"), link("k2", "c1", "c2")]

        let path = try #require(CanvasHitTest.path(for: connections[0], boxes: boxes))

        #expect(CanvasHitTest.connection(
            under: path.point(at: 0.5),
            connections: connections,
            boxes: boxes
        ) == "k2")
    }

    private func viewedZone(_ id: String, x: Double = 0, y: Double = 0) -> ViewedZone {
        ViewedZone(
            id: id,
            name: "Private Zone",
            customName: nil,
            networkZoneId: "private",
            networkTypeId: "generic",
            riskReductionEnabled: true,
            riskReductionPercent: 20,
            x: x,
            y: y,
            width: 600,
            height: 400
        )
    }

    @Test func drawsAZoneAtItsOwnRectangleWhenNothingIsDragging() {
        #expect(CanvasHitTest.rect(for: viewedZone("z1", x: 10, y: 20), drag: nil)
                == CGRect(x: 10, y: 20, width: 600, height: 400))
    }

    @Test func movesTheZoneBeingDraggedByItsHeader() {
        let rect = CanvasHitTest.rect(
            for: viewedZone("z1", x: 10, y: 20),
            drag: (zoneId: "z1", handle: nil, translation: CGSize(width: 30, height: -5))
        )

        #expect(rect == CGRect(x: 40, y: 15, width: 600, height: 400))
    }

    @Test func resizesTheZoneBeingDraggedByAGrip() {
        let rect = CanvasHitTest.rect(
            for: viewedZone("z1"),
            drag: (zoneId: "z1", handle: .bottomRight, translation: CGSize(width: 50, height: 40))
        )

        #expect(rect == CGRect(x: 0, y: 0, width: 650, height: 440))
    }

    @Test func leavesEveryOtherZoneWhereItIs() {
        let rect = CanvasHitTest.rect(
            for: viewedZone("z2", x: 900),
            drag: (zoneId: "z1", handle: nil, translation: CGSize(width: 30, height: 30))
        )

        #expect(rect == CGRect(x: 900, y: 0, width: 600, height: 400))
    }

    @Test func findsTheZoneUnderAPoint() {
        let zones = [viewedZone("z1"), viewedZone("z2", x: 100, y: 100)]

        #expect(CanvasHitTest.zone(under: CGPoint(x: 50, y: 50), zones: zones) == "z1")
        // A later zone wins where two overlap, matching the core's rule.
        #expect(CanvasHitTest.zone(under: CGPoint(x: 200, y: 200), zones: zones) == "z2")
        #expect(CanvasHitTest.zone(under: CGPoint(x: 5000, y: 5000), zones: zones) == nil)
    }
}
