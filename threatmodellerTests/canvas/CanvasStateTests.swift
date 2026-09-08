import CoreGraphics
import Testing
@testable import threatmodeller

@MainActor
struct CanvasStateTests {
    @Test func startsWithNothingSelected() {
        let canvas = CanvasState()

        #expect(canvas.hasSelection == false)
        #expect(canvas.selectedComponentIds.isEmpty)
        #expect(canvas.selectedConnectionIds.isEmpty)
    }

    @Test func aPlainClickSelectsOnlyThatComponent() {
        let canvas = CanvasState()

        canvas.select(componentId: "c1", addingToSelection: false)
        canvas.select(componentId: "c2", addingToSelection: false)

        #expect(canvas.selectedComponentIds == ["c2"])
    }

    @Test func aShiftClickAddsAComponentToTheSelection() {
        let canvas = CanvasState()

        canvas.select(componentId: "c1", addingToSelection: false)
        canvas.select(componentId: "c2", addingToSelection: true)

        #expect(canvas.selectedComponentIds == ["c1", "c2"])
    }

    @Test func aShiftClickOnASelectedComponentRemovesIt() {
        let canvas = CanvasState()

        canvas.select(componentId: "c1", addingToSelection: false)
        canvas.select(componentId: "c2", addingToSelection: true)
        canvas.select(componentId: "c1", addingToSelection: true)

        #expect(canvas.selectedComponentIds == ["c2"])
    }

    @Test func selectingAConnectionDropsTheComponentSelection() {
        let canvas = CanvasState()

        canvas.select(componentId: "c1", addingToSelection: false)
        canvas.select(connectionId: "k1", addingToSelection: false)

        #expect(canvas.selectedComponentIds.isEmpty)
        #expect(canvas.selectedConnectionIds == ["k1"])
        #expect(canvas.isSelected(connectionId: "k1"))
    }

    @Test func aMarqueeReplacesTheWholeSelection() {
        let canvas = CanvasState()

        canvas.select(connectionId: "k1", addingToSelection: false)
        canvas.select(componentIds: ["c1", "c2"])

        #expect(canvas.selectedComponentIds == ["c1", "c2"])
        #expect(canvas.selectedConnectionIds.isEmpty)
    }

    @Test func reportsTheMarqueeRectangleWhileADragIsInFlight() {
        let canvas = CanvasState()

        #expect(canvas.marqueeRect == nil)
        canvas.marquee = (start: CGPoint(x: 40, y: 60), end: CGPoint(x: 10, y: 20))
        #expect(canvas.marqueeRect == CGRect(x: 10, y: 20, width: 30, height: 40))
    }

    @Test func dropsSelectedRowsTheModelNoLongerHolds() {
        let canvas = CanvasState()

        canvas.select(componentIds: ["c1", "c2"])
        canvas.retainOnly(componentIds: ["c2"], connectionIds: [])

        #expect(canvas.selectedComponentIds == ["c2"])
    }

    @Test func escapeCancelsAConnectionDragBeforeItClearsTheSelection() {
        let canvas = CanvasState()

        canvas.select(componentId: "c1", addingToSelection: false)
        canvas.connectionDrag = (sourceComponentId: "c1", currentPoint: CGPoint(x: 5, y: 5))

        #expect(canvas.cancel())
        #expect(canvas.connectionDrag == nil)
        #expect(canvas.selectedComponentIds == ["c1"])

        #expect(canvas.cancel())
        #expect(canvas.hasSelection == false)

        #expect(canvas.cancel() == false)
    }
}
