import CoreGraphics
import Testing
import ThreatModelKit
@testable import threatmodeller

@MainActor
struct TreeCanvasStateTests {
    @Test func retainOnlyDropsASelectedNodeTheTreeNoLongerHoldsAndKeepsOneItHolds() {
        let canvas = TreeCanvasState()

        canvas.select("n1", addingToSelection: false)
        canvas.select("n2", addingToSelection: true)
        canvas.retainOnly(["n2"])

        #expect(canvas.selectedInOrder == ["n2"])
    }

    @Test func retainOnlyDropsASelectedJoinTheTreeNoLongerHolds() {
        let canvas = TreeCanvasState()
        let kept = TreeGraph.Edge(from: "n1", to: "n2")
        let dropped = TreeGraph.Edge(from: "n2", to: "n3")

        canvas.select(kept, addingToSelection: false)
        canvas.select(dropped, addingToSelection: true)
        canvas.retainOnly([], edges: [kept])

        #expect(canvas.selectedEdges == [kept])
    }

    @Test func cancelWithAJoinInFlightClearsTheJoinAndKeepsTheSelectionAndAnswersTrue() {
        let canvas = TreeCanvasState()

        canvas.select("n1", addingToSelection: false)
        canvas.joining = (from: "n1", to: CGPoint(x: 5, y: 5))

        #expect(canvas.cancel())
        #expect(canvas.joining == nil)
        #expect(canvas.selectedInOrder == ["n1"])
    }

    @Test func cancelWithNoJoinAndASelectionClearsTheSelectionAndAnswersTrue() {
        let canvas = TreeCanvasState()

        canvas.select("n1", addingToSelection: false)

        #expect(canvas.cancel())
        #expect(canvas.hasSelection == false)
    }

    @Test func cancelWithNeitherAJoinNorASelectionAnswersFalse() {
        let canvas = TreeCanvasState()

        #expect(canvas.cancel() == false)
    }

    @Test func theSelectionHoldsTheOrderItWasMadeInSoTheFirstSelectedNodeFeedsTheSecond() {
        let canvas = TreeCanvasState()

        canvas.select("n2", addingToSelection: false)
        canvas.select("n1", addingToSelection: true)

        #expect(canvas.selectedInOrder == ["n2", "n1"])
    }
}
