import CoreGraphics
import Testing
import ThreatModelKit
@testable import threatmodeller

/// Clicking a flow where the canvas draws it, and clicking its callout.
///
/// The hit test used to build a curve of its own: a straight line that went
/// round zones but never round nodes, and never stepped aside from a flow
/// already drawn. The picture and the click then disagreed, and a flow that
/// bowed round anything could not be selected at all.
struct FlowClickTests {
    private func component(_ id: String, x: Double, y: Double) -> ViewedComponent {
        ViewedComponent(
            id: id,
            technologyId: "aws-ec2",
            name: "EC2",
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

    private func link(
        _ id: String,
        _ source: String,
        _ target: String,
        described: String? = nil
    ) -> ViewedConnection {
        ViewedConnection(
            id: id,
            sourceComponentId: source,
            targetComponentId: target,
            description: described
        )
    }

    /// Three nodes in a row. The flow from the first to the last has to go
    /// round the one in the middle, so the drawn curve is nowhere near the
    /// straight line between its ends.
    private func aFlowThatGoesRoundANode(
        described: String? = nil
    ) -> (geometry: FlowGeometry, connections: [ViewedConnection]) {
        let components = [
            component("c1", x: 0, y: 0),
            component("c2", x: 500, y: 0),
            component("c3", x: 1000, y: 0)
        ]
        let connections = [link("k1", "c1", "c3", described: described)]
        let geometry = FlowGeometry.of(
            connections: connections,
            boxes: CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero),
            componentsById: Dictionary(uniqueKeysWithValues: components.map { ($0.id, $0) }),
            zones: [],
            guards: [:],
            risks: [:],
            outOfScopeComponentIds: []
        )
        return (geometry, connections)
    }

    @Test func findsTheFlowWhereTheCanvasDrawsIt() throws {
        let world = aFlowThatGoesRoundANode()
        let curve = try #require(world.geometry.curves["k1"])

        // The flow steps round the middle node, so this point is not on the
        // straight line between the two ends.
        let drawn = CGPoint(curve.point(at: 0.5))
        #expect(abs(drawn.y) > ConnectionPath.hitTolerance)

        #expect(world.geometry.connection(under: drawn) == "k1")
    }

    @Test func findsNothingWhereNoFlowIsDrawn() {
        let world = aFlowThatGoesRoundANode()

        #expect(world.geometry.connection(under: CGPoint(x: 500, y: 900)) == nil)
    }

    /// A description is drawn in a box away from the flow. The box is the
    /// part of a flow a reader looks at, so it selects the flow as well.
    @Test func findsTheFlowUnderItsCallout() throws {
        let world = aFlowThatGoesRoundANode(described: "Payment instructions, signed")
        let callout = try #require(world.geometry.callouts.first)

        #expect(callout.connectionId == "k1")
        let middle = CGPoint(
            x: (callout.rect.minX + callout.rect.maxX) / 2,
            y: (callout.rect.minY + callout.rect.maxY) / 2
        )

        #expect(world.geometry.connection(under: middle) == "k1")
    }

    /// Two flows between the same pair step apart, and each is clicked where
    /// it is drawn rather than where the straight line between the ends is.
    @Test func findsEachOfTwoFlowsThatRunBetweenTheSamePair() throws {
        let components = [component("c1", x: 0, y: 0), component("c2", x: 500, y: 0)]
        let connections = [link("k1", "c1", "c2"), link("k2", "c1", "c2")]
        let geometry = FlowGeometry.of(
            connections: connections,
            boxes: CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero),
            componentsById: Dictionary(uniqueKeysWithValues: components.map { ($0.id, $0) }),
            zones: [],
            guards: [:],
            risks: [:],
            outOfScopeComponentIds: []
        )

        let first = try #require(geometry.curves["k1"])
        let second = try #require(geometry.curves["k2"])
        #expect(first != second, "the second flow did not step aside")

        #expect(geometry.connection(under: CGPoint(first.point(at: 0.5))) == "k1")
        #expect(geometry.connection(under: CGPoint(second.point(at: 0.5))) == "k2")
    }

    /// Both flows leave the same point, so a click there belongs to both. The
    /// one drawn last is the one on top, and it takes the click. The ids run
    /// the other way to the drawing order, so a hit test that sorted by id
    /// would answer the other flow.
    @Test func givesTheLaterFlowThePointWhereTwoStillMeet() throws {
        let components = [component("c1", x: 0, y: 0), component("c2", x: 500, y: 0)]
        let connections = [link("k2", "c1", "c2"), link("k1", "c1", "c2")]
        let geometry = FlowGeometry.of(
            connections: connections,
            boxes: CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero),
            componentsById: Dictionary(uniqueKeysWithValues: components.map { ($0.id, $0) }),
            zones: [],
            guards: [:],
            risks: [:],
            outOfScopeComponentIds: []
        )
        let start = CGPoint(try #require(geometry.curves["k1"]).start)

        #expect(geometry.connection(under: start) == "k1")
    }

    @Test func drawsNoFlowWhenAnEndIsMissing() {
        let components = [component("c1", x: 0, y: 0)]
        let geometry = FlowGeometry.of(
            connections: [link("k1", "c1", "c9")],
            boxes: CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero),
            componentsById: Dictionary(uniqueKeysWithValues: components.map { ($0.id, $0) }),
            zones: [],
            guards: [:],
            risks: [:],
            outOfScopeComponentIds: []
        )

        #expect(geometry.curves.isEmpty)
        #expect(geometry.connection(under: CGPoint(x: 100, y: 40)) == nil)
    }


    /// Zoomed out, a flow is thinner on screen, and the same model distance
    /// is a smaller number of screen points. The click keeps the reach it has
    /// on screen, so a flow stays as easy to hit at any zoom.
    @Test func reachesFurtherInModelUnitsWhileTheDiagramIsZoomedOut() throws {
        let world = aFlowThatGoesRoundANode()
        let curve = try #require(world.geometry.curves["k1"])
        let drawn = CGPoint(curve.point(at: 0.5))
        let beside = CGPoint(x: drawn.x, y: drawn.y + ConnectionPath.hitTolerance + 4)

        #expect(world.geometry.connection(under: beside) == nil)
        #expect(world.geometry.connection(under: beside, within: ConnectionPath.hitTolerance * 2) == "k1")
    }
}
