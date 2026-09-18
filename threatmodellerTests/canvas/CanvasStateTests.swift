import CoreGraphics
import Testing
import ThreatModelKit
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
        canvas.retainOnly(componentIds: ["c2"], connectionIds: [], zoneIds: [])

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

    @Test func selectingAZoneDropsEveryOtherSelection() {
        let canvas = CanvasState()

        canvas.select(componentIds: ["c1", "c2"])
        canvas.select(zoneId: "z1")

        #expect(canvas.selectedZoneIds == ["z1"])
        #expect(canvas.selectedComponentIds.isEmpty)
        #expect(canvas.selectedConnectionIds.isEmpty)
        #expect(canvas.hasSelection)
    }

    @Test func selectingAComponentDropsTheZoneSelection() {
        let canvas = CanvasState()

        canvas.select(zoneId: "z1")
        canvas.select(componentId: "c1", addingToSelection: false)

        #expect(canvas.selectedZoneIds.isEmpty)
    }

    @Test func dropsASelectedZoneTheModelNoLongerHolds() {
        let canvas = CanvasState()

        canvas.select(zoneId: "z1")
        canvas.retainOnly(componentIds: [], connectionIds: [], zoneIds: [])

        #expect(canvas.selectedZoneIds.isEmpty)
    }

    @Test func reportsTheZoneDraftRectangleWhileTheUserDrawsIt() {
        let canvas = CanvasState()

        #expect(canvas.zoneDraftRect == nil)
        canvas.zoneDraft = (start: CGPoint(x: 90, y: 80), end: CGPoint(x: 10, y: 20))
        #expect(canvas.zoneDraftRect == CGRect(x: 10, y: 20, width: 80, height: 60))
    }

    @Test func escapeLeavesTheZoneDrawingModeBeforeItClearsTheSelection() {
        let canvas = CanvasState()

        canvas.select(zoneId: "z1")
        canvas.startDrawingZone()
        #expect(canvas.isDrawingZone)

        #expect(canvas.cancel())
        #expect(canvas.isDrawingZone == false)
        #expect(canvas.zoneDraft == nil)
        #expect(canvas.selectedZoneIds == ["z1"])

        #expect(canvas.cancel())
        #expect(canvas.hasSelection == false)
    }

    /// The pointer shows a closed hand while a pan is in flight, so the state
    /// says whether one is.
    @Test func saysWhetherAPanIsInFlight() {
        let canvas = CanvasState()

        #expect(canvas.isPanning == false)
        canvas.isPanning = true
        #expect(canvas.isPanning)
    }

    @Test func cancelsAConnectionDragBeforeItLeavesTheZoneMode() {
        let canvas = CanvasState()

        canvas.startDrawingZone()
        canvas.connectionDrag = (sourceComponentId: "c1", currentPoint: .zero)

        #expect(canvas.cancel())
        #expect(canvas.connectionDrag == nil)
        #expect(canvas.isDrawingZone)
    }

    /// The neighbours stepper holds its value while the tag filter's own
    /// tags change, so a person does not re-set it for every tag they pick.
    @Test func theNeighbourDepthHoldsWhilePickedTagsChange() {
        let canvas = CanvasState()

        canvas.setNeighbourDepth(2)
        canvas.pick(tag: "payments")
        canvas.pick(tag: "payments")
        canvas.clearTagFilter()

        #expect(canvas.tagFilter.neighbourDepth == 2)
    }

    /// A hidden element that stayed selected would still show its panel and
    /// still move under an arrow key, so picking a tag drops the selection.
    @Test func pickingATagDropsTheSelectionSoAHiddenElementShowsNoPanel() {
        let canvas = CanvasState()
        canvas.select(componentId: "x", addingToSelection: false)

        canvas.pick(tag: "payments")

        #expect(canvas.hasSelection == false)
    }

    @Test func changingTheNeighbourDepthLeavesTheSelectionAsItWas() {
        let canvas = CanvasState()
        canvas.select(componentId: "x", addingToSelection: false)

        canvas.setNeighbourDepth(2)

        #expect(canvas.selectedComponentIds == ["x"])
    }

    @Test func clearingTheTagFilterLeavesTheSelectionAsItWas() {
        let canvas = CanvasState()
        canvas.select(componentId: "x", addingToSelection: false)

        canvas.clearTagFilter()

        #expect(canvas.selectedComponentIds == ["x"])
    }

    // MARK: Focus

    @Test func focusSetsTheFocusedComponentAndClearsTheSelection() {
        let canvas = CanvasState()
        canvas.select(componentId: "x", addingToSelection: false)

        canvas.focus(componentId: "c1")

        #expect(canvas.focusedComponentId == "c1")
        #expect(canvas.hasSelection == false)
    }

    /// Focus and the tag filter never both narrow the canvas: turning Focus
    /// on always clears the tag filter, so a component the filter was hiding
    /// is drawn once Focus picks it.
    @Test func focusingAComponentClearsAnActiveTagFilter() {
        let canvas = CanvasState()
        canvas.pick(tag: "payments")

        canvas.focus(componentId: "c1")

        #expect(canvas.tagFilter.isNarrowing == false)
    }

    @Test func clearingTheTagFilterAlsoClearsFocus() {
        let canvas = CanvasState()
        canvas.focus(componentId: "c1")

        canvas.clearTagFilter()

        #expect(canvas.focusedComponentId == nil)
    }

    // MARK: drawn(in:) writes no observed state

    /// A SwiftUI view body reads `drawn(in:)`, so it must write no property
    /// of `CanvasState`: writing observed state from a view body is a state
    /// change during a view update.
    @Test func twoCallsToDrawnWriteNoObservedStateOfCanvasState() {
        let canvas = CanvasState()
        let model = ViewThreatModelResponse(name: "Payments", components: [], connections: [], zones: [])

        _ = canvas.drawn(in: model)
        let positionsAfterFirstCall = canvas.narrowedComponentPositions
        let zonesAfterFirstCall = canvas.narrowedZoneRects
        let transformAfterFirstCall = canvas.transform

        _ = canvas.drawn(in: model)

        #expect(canvas.narrowedComponentPositions == positionsAfterFirstCall)
        #expect(canvas.narrowedZoneRects == zonesAfterFirstCall)
        #expect(canvas.transform == transformAfterFirstCall)
    }

    @Test func aLayoutRunOverAnEmptyDrawnSetKeepsTheNarrowedCoordinates() {
        let canvas = CanvasState()
        let component = ViewedComponent(
            id: "c1",
            technologyId: "aws-ec2",
            name: "c1",
            customName: nil,
            providerId: "aws",
            categoryId: "compute",
            x: 0,
            y: 0,
            sensitivityId: "internal",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: nil,
            tags: ["payments"]
        )
        let model = ViewThreatModelResponse(name: "Payments", components: [component], connections: [], zones: [])
        let layouts = FakeNarrowedDiagramLayouts(
            model: model,
            response: .laidOut(components: [LaidOutComponent(id: "c1", x: 5, y: 5)], zones: [])
        )
        canvas.layouts = layouts

        canvas.pick(tag: "payments")
        let positionsAfterALaidOutRun = canvas.narrowedComponentPositions
        #expect(positionsAfterALaidOutRun.isEmpty == false)

        layouts.response = .nothingToLayOut
        canvas.setNeighbourDepth(2)

        #expect(canvas.narrowedComponentPositions == positionsAfterALaidOutRun)
    }
}

/// A fake `layouts` the tests set on `CanvasState`, so a test can choose what
/// a layout run returns without a real layout use case.
@MainActor
private final class FakeNarrowedDiagramLayouts: NarrowedDiagramLayouts {
    let model: ViewThreatModelResponse
    var response: LayOutSubsetResponse

    init(model: ViewThreatModelResponse, response: LayOutSubsetResponse) {
        self.model = model
        self.response = response
    }

    func layOutSubset(componentIds: [String], zoneIds: [String]) -> LayOutSubsetResponse {
        response
    }
}
