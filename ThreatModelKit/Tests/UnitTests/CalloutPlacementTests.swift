import Foundation
import Testing
import ThreatModelKit

@Suite("Putting a label where the diagram is empty")
struct CalloutPlacementTests {
    private func label(
        _ id: String,
        _ text: String,
        from: Point = Point(x: 0, y: 0),
        to: Point = Point(x: 400, y: 0)
    ) -> (connectionId: String, text: String, curve: FlowCurve) {
        (id, text, FlowCurve(from: from, to: to))
    }

    @Test func placesOneLabelBesideItsFlow() throws {
        let placed = CalloutPlacement.place([label("f1", "MCP over unix domain socket")], nodes: [], flows: [])

        #expect(placed.count == 1)
        let callout = try #require(placed.first)
        #expect(callout.connectionId == "f1")
        #expect(callout.text == "MCP over unix domain socket")
        #expect(callout.rect.size.width == CalloutPlacement.width)
    }

    @Test func saysNothingForAFlowWithNothingToSay() {
        #expect(CalloutPlacement.place([label("f1", "")], nodes: [], flows: []).isEmpty)
    }

    @Test func reachesTheFlowItLabels() throws {
        let placed = CalloutPlacement.place([label("f1", "HTTPS")], nodes: [], flows: [])
        let callout = try #require(placed.first)

        #expect(callout.anchor == FlowCurve(from: Point(x: 0, y: 0), to: Point(x: 400, y: 0)).point(at: 0.5))
    }

    @Test func staysOffANode() throws {
        // Every close place above the flow is a node, so the box goes below.
        let nodes = [Rect(x: -400, y: -400, width: 1200, height: 380)]
        let placed = CalloutPlacement.place(
            [label("f1", "MCP over unix domain socket, newline-delimited JSON")],
            nodes: nodes,
            flows: []
        )
        let callout = try #require(placed.first)

        #expect(CalloutPlacement.overlap(callout.rect, nodes[0]) == false)
    }

    @Test func staysOffALabelAlreadyPlaced() throws {
        let placed = CalloutPlacement.place(
            [
                label("f1", "MCP over unix domain socket"),
                label("f2", "NSXPCConnection, signature-validated", from: Point(x: 0, y: 40), to: Point(x: 400, y: 40))
            ],
            nodes: [],
            flows: []
        )

        #expect(placed.count == 2)
        #expect(CalloutPlacement.overlap(placed[0].rect, placed[1].rect) == false)
    }

    @Test func growsTheBoxForALongerText() {
        let short = CalloutPlacement.size(of: "HTTPS")
        let long = CalloutPlacement.size(
            of: "MCP over unix domain socket, newline-delimited JSON, signature-validated by ConnectionID"
        )

        #expect(long.height > short.height)
        #expect(long.width == short.width)
    }

    @Test func placesTheSameDiagramTheSameWayTwice() {
        let labels = [
            label("f1", "MCP over unix domain socket"),
            label("f2", "HTTPS", from: Point(x: 0, y: 200), to: Point(x: 400, y: 200))
        ]
        let nodes = [Rect(x: 100, y: -60, width: 160, height: 72)]

        #expect(
            CalloutPlacement.place(labels, nodes: nodes, flows: [])
                == CalloutPlacement.place(labels, nodes: nodes, flows: [])
        )
    }
}

@Suite("Labels keeping their distance")
struct CalloutSpacingTests {
    private func label(
        _ id: String,
        _ text: String,
        y: Double
    ) -> (connectionId: String, text: String, curve: FlowCurve) {
        (id, text, FlowCurve(from: Point(x: 0, y: y), to: Point(x: 400, y: y)))
    }

    @Test func leavesBlankBetweenTwoLabels() {
        let placed = CalloutPlacement.place(
            [
                label("f1", "MCP over unix domain socket", y: 0),
                label("f2", "NSXPCConnection, signature-validated", y: 30)
            ],
            nodes: [],
            flows: []
        )

        #expect(placed.count == 2)
        #expect(CalloutPlacement.crowds(placed[0].rect, placed[1].rect) == false)
    }

    @Test func stillPlacesEveryLabelWhenThereIsNoRoomToSpare() {
        let many = (0 ..< 8).map { label("f\($0)", "a label worth reading", y: Double($0) * 12) }
        let placed = CalloutPlacement.place(many, nodes: [], flows: [])

        #expect(placed.count == 8)
    }
}
