import CoreGraphics
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// More than one zone selected, moved, deleted and reordered together.
@MainActor
@Suite("Working on several zones at once")
struct ZoneSelectionTests {
    private func session() -> ThreatModelSession {
        ThreatModelSession(useCases: TestDependencies())
    }

    /// Two zones side by side, and the identifiers they were given.
    private func twoZones() throws -> (ThreatModelSession, CanvasState, String, String) {
        let session = session()
        let left = try #require(session.addZone(x: 0, y: 0, width: 300, height: 200))
        let right = try #require(session.addZone(x: 400, y: 0, width: 300, height: 200))
        return (session, CanvasState(), left, right)
    }

    @Test func aShiftClickAddsASecondZoneToTheSelection() throws {
        let (_, canvas, left, right) = try twoZones()

        canvas.select(zoneId: left, addingToSelection: false)
        canvas.select(zoneId: right, addingToSelection: true)

        #expect(canvas.selectedZoneIds == [left, right])
    }

    @Test func aSecondShiftClickTakesTheZoneOutOfTheSelection() throws {
        let (_, canvas, left, right) = try twoZones()

        canvas.select(zoneId: left, addingToSelection: false)
        canvas.select(zoneId: right, addingToSelection: true)
        canvas.select(zoneId: right, addingToSelection: true)

        #expect(canvas.selectedZoneIds == [left])
    }

    @Test func aPlainClickSelectsThatZoneAlone() throws {
        let (_, canvas, left, right) = try twoZones()

        canvas.select(zoneId: left, addingToSelection: false)
        canvas.select(zoneId: right, addingToSelection: true)
        canvas.select(zoneId: right, addingToSelection: false)

        #expect(canvas.selectedZoneIds == [right])
    }

    /// A marquee takes a zone only when it covers all of it, so a marquee
    /// drawn inside a zone gathers the nodes and leaves the zone alone.
    @Test func aMarqueeTakesTheZonesItCoversWhole() throws {
        let (_, _, left, right) = try twoZones()
        let zones = [
            (id: left, rect: CGRect(x: 0, y: 0, width: 300, height: 200)),
            (id: right, rect: CGRect(x: 400, y: 0, width: 300, height: 200))
        ]

        let all = MarqueeSelection.selectedZones(
            in: CGRect(x: -10, y: -10, width: 800, height: 400),
            from: zones
        )
        let inside = MarqueeSelection.selectedZones(
            in: CGRect(x: 20, y: 20, width: 100, height: 100),
            from: zones
        )

        #expect(all == [left, right])
        #expect(inside.isEmpty)
    }

    @Test func draggingOneHeaderMovesEverySelectedZone() throws {
        let (session, canvas, left, right) = try twoZones()
        canvas.select(zoneId: left, addingToSelection: false)
        canvas.select(zoneId: right, addingToSelection: true)
        let gestures = CanvasGestures(session: session, canvas: canvas)

        gestures.zoneDragChanged(left, handle: nil, translation: CGSize(width: 50, height: 30))
        gestures.zoneDragEnded(left, handle: nil, translation: CGSize(width: 50, height: 30))

        let moved = Dictionary(uniqueKeysWithValues: session.canvas.zones.map { ($0.id, $0) })
        #expect(moved[left]?.x == 50)
        #expect(moved[left]?.y == 30)
        #expect(moved[right]?.x == 450)
        #expect(moved[right]?.y == 30)
    }

    @Test func oneUndoTakesBackTheWholeGroupMove() throws {
        let (session, canvas, left, right) = try twoZones()
        canvas.select(zoneId: left, addingToSelection: false)
        canvas.select(zoneId: right, addingToSelection: true)
        let gestures = CanvasGestures(session: session, canvas: canvas)
        gestures.zoneDragChanged(left, handle: nil, translation: CGSize(width: 50, height: 30))
        gestures.zoneDragEnded(left, handle: nil, translation: CGSize(width: 50, height: 30))

        session.undo()

        let back = Dictionary(uniqueKeysWithValues: session.canvas.zones.map { ($0.id, $0) })
        #expect(back[left]?.x == 0)
        #expect(back[right]?.x == 400)
    }

    /// A drag on a zone the person has not selected takes the selection with
    /// it, so a group move never happens by surprise.
    @Test func draggingAZoneOutsideTheSelectionMovesOnlyThatZone() throws {
        let (session, canvas, left, right) = try twoZones()
        canvas.select(zoneId: left, addingToSelection: false)
        let gestures = CanvasGestures(session: session, canvas: canvas)

        gestures.zoneDragChanged(right, handle: nil, translation: CGSize(width: 50, height: 0))
        gestures.zoneDragEnded(right, handle: nil, translation: CGSize(width: 50, height: 0))

        let moved = Dictionary(uniqueKeysWithValues: session.canvas.zones.map { ($0.id, $0) })
        #expect(moved[right]?.x == 450)
        #expect(moved[left]?.x == 0)
        #expect(canvas.selectedZoneIds == [right])
    }

    @Test func deletingTheSelectionRemovesEverySelectedZone() throws {
        let (session, canvas, left, right) = try twoZones()
        canvas.select(zoneId: left, addingToSelection: false)
        canvas.select(zoneId: right, addingToSelection: true)

        CanvasGestures(session: session, canvas: canvas).deleteSelection()

        #expect(session.canvas.zones.isEmpty)
        #expect(canvas.selectedZoneIds.isEmpty)
    }

    @Test func bringingAZoneToTheFrontPutsItLastInTheDrawingOrder() throws {
        let (session, canvas, left, right) = try twoZones()
        canvas.select(zoneId: left, addingToSelection: false)

        CanvasGestures(session: session, canvas: canvas).reorderSelectedZones(.front)

        #expect(session.canvas.zones.map(\.id) == [right, left])
    }

    @Test func sendingAZoneToTheBackPutsItFirstInTheDrawingOrder() throws {
        let (session, canvas, left, right) = try twoZones()
        canvas.select(zoneId: right, addingToSelection: false)

        CanvasGestures(session: session, canvas: canvas).reorderSelectedZones(.back)

        #expect(session.canvas.zones.map(\.id) == [right, left])
    }

    @Test func reorderingWithNoZoneSelectedChangesNothing() throws {
        let (session, canvas, left, right) = try twoZones()

        CanvasGestures(session: session, canvas: canvas).reorderSelectedZones(.front)

        #expect(session.canvas.zones.map(\.id) == [left, right])
    }

    /// The picture follows the whole group while the drag is in flight, not
    /// only the zone the pointer is on.
    @Test func everySelectedZoneDrawsWhereTheGroupIsGoing() throws {
        let (session, canvas, left, right) = try twoZones()
        canvas.select(zoneId: left, addingToSelection: false)
        canvas.select(zoneId: right, addingToSelection: true)
        canvas.zoneDrag = (zoneId: left, handle: nil, translation: CGSize(width: 50, height: 30))

        let rects = session.canvas.zones.map {
            CanvasHitTest.rect(for: $0, drag: canvas.zoneDrag, movingWith: canvas.selectedZoneIds)
        }

        #expect(rects[0].origin == CGPoint(x: 50, y: 30))
        #expect(rects[1].origin == CGPoint(x: 450, y: 30))
    }
}

/// One edit writes one change, not one per keystroke and not one per slider
/// step.
@Suite("An edit in flight")
struct DeferredEditTests {
    @Test func typingWritesNothingUntilTheEditEnds() {
        var edit = DeferredEdit<String>()

        edit.edit("P")
        edit.edit("Pa")
        edit.edit("Pay")

        #expect(edit.isEditing)
        #expect(edit.shown("") == "Pay")
    }

    @Test func theEndOfTheEditWritesOnce() {
        var edit = DeferredEdit<String>()
        edit.edit("P")
        edit.edit("Pay")

        let written = edit.end(from: "")

        #expect(written == "Pay")
        #expect(edit.isEditing == false)
        #expect(edit.end(from: "") == nil)
    }

    @Test func anEditThatChangedNothingWritesNothing() {
        var edit = DeferredEdit<String>()
        edit.edit("Payments")

        #expect(edit.end(from: "Payments") == nil)
    }

    @Test func aControlWithNoEditInFlightShowsTheModelsValue() {
        var edit = DeferredEdit<Double>()
        edit.edit(45)
        _ = edit.end(from: 20)

        #expect(edit.shown(45) == 45)
    }

    @Test func aCancelledEditWritesNothing() {
        var edit = DeferredEdit<Double>()
        edit.edit(80)

        edit.cancel()

        #expect(edit.isEditing == false)
        #expect(edit.shown(20) == 20)
    }

    /// A drag across the range steps many times and writes once.
    @Test func aDragOfManyStepsWritesOneChange() {
        var edit = DeferredEdit<Double>()
        var writes = 0

        for step in stride(from: 5.0, through: 60.0, by: 5.0) {
            edit.edit(step)
        }
        if edit.end(from: 20) != nil { writes += 1 }

        #expect(writes == 1)
    }
}
