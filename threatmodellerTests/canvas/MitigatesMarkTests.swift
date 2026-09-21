import CoreGraphics
import Testing
import ThreatModelKit
@testable import threatmodeller

/// The mark the canvas draws for a `mitigates` edge, and what a click on it
/// hits.
///
/// A `mitigates` edge states that one component lowers a threat set on
/// another. The canvas drew nothing for one, so a reader opened a panel per
/// pair to see the protection structure.
struct MitigatesMarkTests {
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

    private func edge(
        _ source: String,
        _ target: String,
        status: String = "live"
    ) -> ViewedMitigation {
        ViewedMitigation(
            sourceComponentId: source,
            targetComponentId: target,
            status: status
        )
    }

    private func twoNodes() -> [ViewedComponent] {
        [component("c1", x: 0, y: 0), component("c2", x: 500, y: 0)]
    }

    private func geometry(
        _ mitigations: [ViewedMitigation],
        components: [ViewedComponent]
    ) -> MitigatesGeometry {
        MitigatesGeometry.of(
            mitigations: mitigations,
            boxes: CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero)
        )
    }

    // MARK: what is drawn

    @Test func drawsOneMarkForEachEdge() {
        let components = [
            component("c1", x: 0, y: 0),
            component("c2", x: 500, y: 0),
            component("c3", x: 500, y: 300)
        ]
        let marks = geometry([edge("c1", "c2"), edge("c1", "c3")], components: components).marks

        #expect(marks.count == 2)
        #expect(marks.map(\.targetComponentId) == ["c2", "c3"])
    }

    @Test func drawsNoMarkWhenTheModelHoldsNoEdge() {
        #expect(geometry([], components: twoNodes()).marks.isEmpty)
    }

    /// The canvas draws a removed edge no mark. The model is what the layer
    /// reads, so an edge the model no longer holds leaves the picture.
    @Test func drawsNoMarkForAnEdgeThatWasRemoved() {
        let components = twoNodes()
        let before = geometry([edge("c1", "c2")], components: components)
        let after = geometry([], components: components)

        #expect(before.marks.count == 1)
        #expect(after.marks.isEmpty)
        #expect(after.mark(under: before.marks[0].apex) == nil)
    }

    @Test func drawsNoMarkWhenAnEndIsMissing() {
        #expect(geometry([edge("c1", "c9")], components: twoNodes()).marks.isEmpty)
    }

    @Test func drawsNoMarkForAnEdgeOnToItself() {
        #expect(geometry([edge("c1", "c1")], components: twoNodes()).marks.isEmpty)
    }

    // MARK: the mark is not a flow

    /// The mark bows off the straight line between the two boxes, so a flow
    /// between the same pair and the mark never lie on each other. A click on
    /// the mark reaches the edge and not the flow.
    @Test func standsClearOfTheFlowBetweenTheSamePair() throws {
        let components = twoNodes()
        let boxes = CanvasHitTest.boxes(for: components, selected: [], dragTranslation: .zero)
        let flows = FlowGeometry.of(
            connections: [
                ViewedConnection(id: "k1", sourceComponentId: "c1", targetComponentId: "c2")
            ],
            boxes: boxes,
            componentsById: Dictionary(uniqueKeysWithValues: components.map { ($0.id, $0) }),
            zones: [],
            guards: [:],
            risks: [:],
            outOfScopeComponentIds: []
        )
        let mark = try #require(geometry([edge("c1", "c2")], components: components).marks.first)
        let curve = try #require(flows.curves["k1"])

        let apart = (0...40).reduce(CGFloat.infinity) { shortest, step in
            let sample = CGPoint(curve.point(at: Double(step) / 40))
            return min(shortest, hypot(sample.x - mark.apex.x, sample.y - mark.apex.y))
        }

        #expect(apart > MitigatesGeometry.hitTolerance)
        #expect(flows.connection(under: mark.apex) == nil)
    }

    /// A flow carries an arrowhead and the risk colour. The mark carries a
    /// shield and no arrowhead, so the two read as different things.
    @Test func carriesAShieldAndNoArrowhead() throws {
        let mark = try #require(geometry([edge("c1", "c2")], components: twoNodes()).marks.first)

        #expect(mark.shieldRect.width == MitigatesGeometry.shieldSize.width)
        #expect(mark.shieldRect.height == MitigatesGeometry.shieldSize.height)
        #expect(mark.shieldRect.contains(mark.apex))
    }

    // MARK: assumed against adopted

    @Test func drawsAnAssumedEdgeBrokenAndHollow() throws {
        let components = twoNodes()
        let adopted = try #require(
            geometry([edge("c1", "c2", status: "live")], components: components).marks.first
        )
        let assumed = try #require(
            geometry([edge("c1", "c2", status: "proposed")], components: components).marks.first
        )

        #expect(adopted.isAssumed == false)
        #expect(assumed.isAssumed)
        #expect(adopted.dash != assumed.dash)
        #expect(adopted.isShieldFilled != assumed.isShieldFilled)
        #expect(adopted.isShieldFilled)
    }

    /// The two states draw on the same curve, so only the stroke and the
    /// shield tell them apart. A reader clicks either one in the same place.
    @Test func drawsBothStatesOnTheSameCurve() throws {
        let components = twoNodes()
        let adopted = try #require(
            geometry([edge("c1", "c2", status: "live")], components: components).marks.first
        )
        let assumed = try #require(
            geometry([edge("c1", "c2", status: "proposed")], components: components).marks.first
        )

        #expect(adopted.apex == assumed.apex)
    }

    // MARK: what a click hits

    @Test func findsTheEdgeUnderTheMark() throws {
        let world = geometry([edge("c1", "c2")], components: twoNodes())
        let mark = try #require(world.marks.first)

        #expect(world.mark(under: mark.point(at: 0.25))?.targetComponentId == "c2")
        #expect(world.mark(under: mark.apex)?.sourceComponentId == "c1")
    }

    @Test func findsTheEdgeUnderItsShield() throws {
        let world = geometry([edge("c1", "c2")], components: twoNodes())
        let mark = try #require(world.marks.first)
        let corner = CGPoint(x: mark.shieldRect.minX + 1, y: mark.shieldRect.minY + 1)

        #expect(world.mark(under: corner)?.sourceComponentId == "c1")
    }

    @Test func findsNothingWhereNoMarkIsDrawn() {
        let world = geometry([edge("c1", "c2")], components: twoNodes())

        #expect(world.mark(under: CGPoint(x: 250, y: 900)) == nil)
    }

    @Test func reachesFurtherInModelUnitsWhileTheDiagramIsZoomedOutForAMitigatesMark() throws {
        let world = geometry([edge("c1", "c2")], components: twoNodes())
        let mark = try #require(world.marks.first)
        let quarter = mark.point(at: 0.15)
        let beside = CGPoint(x: quarter.x, y: quarter.y - MitigatesGeometry.hitTolerance - 6)

        #expect(world.mark(under: beside) == nil)
        #expect(world.mark(under: beside, within: MitigatesGeometry.hitTolerance * 4) != nil)
    }

    // MARK: which way round the panel reads the pair

    /// The bar under the canvas reads "X lowers threats on Y". The edge holds
    /// the direction, so the pair is ordered by the edge and not by the order
    /// the model holds the two components in.
    @Test func putsTheProtectorFirstWhenThePairHoldsAnEdge() throws {
        let components = twoNodes()
        let pair = try #require(
            MitigatesGeometry.ordered(
                [components[1], components[0]],
                mitigations: [edge("c1", "c2")]
            )
        )

        #expect(pair.source.id == "c1")
        #expect(pair.target.id == "c2")
    }

    @Test func keepsTheModelOrderWhenThePairHoldsNoEdge() throws {
        let components = twoNodes()
        let pair = try #require(
            MitigatesGeometry.ordered([components[1], components[0]], mitigations: [])
        )

        #expect(pair.source.id == "c2")
        #expect(pair.target.id == "c1")
    }

    @Test func ordersNoPairWhenTwoComponentsAreNotSelected() {
        let components = twoNodes()

        if let pair = MitigatesGeometry.ordered([components[0]], mitigations: []) {
            Issue.record("one component made a pair: \(pair.source.id)")
        }
    }
}
