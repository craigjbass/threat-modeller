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
}
