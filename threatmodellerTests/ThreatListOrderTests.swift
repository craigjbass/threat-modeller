import CoreGraphics
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The order the threat list draws.
///
/// A person answers the register one card at a time, top to bottom, so the
/// order must hold still while they do. Worst first is right for the report
/// and for the first read; it is wrong to re-apply on every keystroke.
@MainActor
@Suite("The order the threat list holds")
struct ThreatListOrderTests {
    private func session() -> ThreatModelSession {
        ThreatModelSession(useCases: TestDependencies())
    }

    /// Two EC2 nodes, so the list holds six rows in two groups.
    private func twoNodes() -> ThreatModelSession {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-ec2", x: 400, y: 0)
        return session
    }

    private func sorted(_ session: ThreatModelSession) -> [String] {
        session.threats.map(\.threatKey)
    }

    @Test func startsWorstFirst() {
        let session = twoNodes()

        #expect(session.threats.map(\.riskScore) == session.threats.map(\.riskScore).sorted(by: >))
        #expect(session.rowsOutOfOrder == 0)
    }

    @Test func movesNoCardWhenAControlIsTicked() throws {
        let session = twoNodes()
        let before = sorted(session)
        let top = try #require(session.threats.first)
        let control = try #require(top.controls.first)

        session.setControl(key: control.key, implemented: true)

        #expect(sorted(session) == before)
        let after = try #require(session.threats.first { $0.threatKey == top.threatKey })
        #expect(after.riskScore < top.riskScore)
    }

    @Test func showsTheReorderButtonAfterAnEditThatChangesAScore() throws {
        let session = twoNodes()
        let control = try #require(session.threats.first?.controls.first)

        session.setControl(key: control.key, implemented: true)

        #expect(session.rowsOutOfOrder > 0)
    }

    @Test func movesNoCardWhenASeverityIsOverridden() throws {
        let session = twoNodes()
        let before = sorted(session)
        let top = try #require(session.threats.first)

        session.overrideSeverity(overrideKey: top.overrideKey, severityId: "low")

        #expect(sorted(session) == before)
        #expect(session.rowsOutOfOrder > 0)
    }

    @Test func movesNoCardWhenALikelihoodFindingIsWritten() throws {
        let session = twoNodes()
        let before = sorted(session)
        let top = try #require(session.threats.first)

        session.setLikelihoodFinding(
            threatKey: top.threatKey,
            label: "no in-the-wild use",
            tier: "research",
            prior: nil,
            rationale: "every report is researcher-found",
            sources: []
        )

        #expect(sorted(session) == before)
        #expect(session.rowsOutOfOrder > 0)
    }

    @Test func movesNoCardWhenACompensatingControlIsWritten() throws {
        let session = twoNodes()
        let before = sorted(session)
        let top = try #require(session.threats.first)

        session.setCompensatingControl(
            threatKey: top.threatKey,
            label: "the network blocks it",
            reducesRiskBy: 50,
            rationale: "the egress rule is in place"
        )

        #expect(sorted(session) == before)
    }

    @Test func sortsAndHidesTheButtonWhenTheUserReorders() throws {
        let session = twoNodes()
        let control = try #require(session.threats.first?.controls.first)
        session.setControl(key: control.key, implemented: true)
        #expect(session.rowsOutOfOrder > 0)

        session.resortThreats()

        #expect(session.threats.map(\.riskScore) == session.threats.map(\.riskScore).sorted(by: >))
        #expect(session.rowsOutOfOrder == 0)
    }

    @Test func sortsWithNoButtonWhenAModelLoads() throws {
        let session = twoNodes()
        let control = try #require(session.threats.first?.controls.first)
        session.setControl(key: control.key, implemented: true)
        #expect(session.rowsOutOfOrder > 0)

        session.loadSample(FakeSampleModels.sampleId)

        #expect(session.rowsOutOfOrder == 0)
        #expect(session.threats.map(\.riskScore) == session.threats.map(\.riskScore).sorted(by: >))
    }

    /// A threat the architecture newly raises enters at its sorted place, and
    /// neither adding nor removing shows the button on its own.
    @Test func entersANewThreatAtItsSortedPlace() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)

        session.add(technologyId: "aws-rds", x: 400, y: 0)

        #expect(session.rowsOutOfOrder == 0)
        #expect(session.threats.map(\.riskScore) == session.threats.map(\.riskScore).sorted(by: >))
    }

    @Test func leavesTheRestWhenAThreatIsNoLongerRaised() throws {
        let session = twoNodes()
        let second = try #require(session.canvas.components.last?.id)

        _ = session.removeComponents([second])

        #expect(session.rowsOutOfOrder == 0)
        #expect(session.threats.allSatisfy { $0.source.id != "component:\(second)" })
    }

    /// The held order is a pure function of the rows and the order before it.
    @Test func keepsTheHeldOrderAndPlacesWhatIsNew() {
        let session = twoNodes()
        let assessed = session.threats
        let held = ThreatModelSession.held(
            assessed,
            inOrderOf: [assessed[2].threatKey, assessed[0].threatKey]
        )

        // Every row is there once, and the two the previous order named keep
        // the order it gave them.
        #expect(held.count == assessed.count)
        #expect(Set(held.map(\.threatKey)) == Set(assessed.map(\.threatKey)))
        let places = [assessed[2].threatKey, assessed[0].threatKey].compactMap { key in
            held.firstIndex { $0.threatKey == key }
        }
        #expect(places == places.sorted())
    }

    @Test func countsEveryRowASortWouldMove() {
        let session = twoNodes()
        let assessed = session.threats
        let swapped = [assessed[1], assessed[0]] + assessed.dropFirst(2)

        #expect(ThreatModelSession.rowsOutOfOrder(drawn: swapped, sorted: assessed) == 2)
        #expect(ThreatModelSession.rowsOutOfOrder(drawn: assessed, sorted: assessed) == 0)
    }
}

/// Opening and closing the groups of the threat list.
@MainActor
@Suite("The groups the threat list draws closed")
struct ThreatGroupCollapseTests {
    private func session() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        return session
    }

    private func groupIds(_ session: ThreatModelSession) -> [String] {
        var seen: [String] = []
        for threat in session.threats where seen.contains(threat.source.id) == false {
            seen.append(threat.source.id)
        }
        return seen
    }

    @Test func startsWithEveryGroupOpen() {
        #expect(session().collapsedGroups.isEmpty)
    }

    @Test func closesAndOpensOneGroup() throws {
        let session = session()
        let first = try #require(groupIds(session).first)

        session.toggleGroup(first)
        #expect(session.collapsedGroups == [first])

        session.toggleGroup(first)
        #expect(session.collapsedGroups.isEmpty)
    }

    @Test func closesEveryGroupAndOpensThemAgain() {
        let session = session()
        let ids = groupIds(session)
        #expect(ids.count == 2)

        session.collapseEveryGroup(ids)
        #expect(session.collapsedGroups == Set(ids))

        session.expandEveryGroup()
        #expect(session.collapsedGroups.isEmpty)
    }

    /// Option-clicking a group's disclosure does the same as the two buttons.
    @Test func closesEveryGroupOnAnOptionClickOfAnOpenGroup() throws {
        let session = session()
        let ids = groupIds(session)
        let first = try #require(ids.first)

        session.toggleGroup(first, everyGroupId: ids, appliesToEveryGroup: true)

        #expect(session.collapsedGroups == Set(ids))
    }

    @Test func opensEveryGroupOnAnOptionClickOfAClosedGroup() throws {
        let session = session()
        let ids = groupIds(session)
        let first = try #require(ids.first)
        session.collapseEveryGroup(ids)

        session.toggleGroup(first, everyGroupId: ids, appliesToEveryGroup: true)

        #expect(session.collapsedGroups.isEmpty)
    }

    /// The set lives on the session, so it survives every stage change and
    /// every edit for as long as the system is open.
    @Test func keepsTheClosedGroupsThroughAnEdit() throws {
        let session = session()
        let ids = groupIds(session)
        session.collapseEveryGroup(ids)
        let control = try #require(session.threats.first?.controls.first)

        session.setControl(key: control.key, implemented: true)

        #expect(session.collapsedGroups == Set(ids))
    }
}

/// Deleting a custom technology asks first, because it deletes every
/// component that uses it.
@MainActor
@Suite("Deleting a technology this model defines")
struct DeleteCustomTechnologyTests {
    private func session() -> ThreatModelSession {
        ThreatModelSession(useCases: TestDependencies())
    }

    private func withACustomTechnology() -> (ThreatModelSession, String) {
        let session = session()
        let id = session.createCustomTechnology(
            name: "Cribl Stream",
            categoryId: "compute",
            description: "A pipeline",
            threatIds: ["credential-theft"],
            enforcesEncryption: false
        )
        return (session, id ?? "")
    }

    @Test func statesHowManyComponentsUseIt() {
        #expect(
            TechnologyRow.question(name: "Cribl Stream", components: 0)
                == "No component uses Cribl Stream. Deleting it removes it from this model."
        )
        #expect(TechnologyRow.question(name: "Cribl Stream", components: 1).hasPrefix("1 component uses"))
        #expect(
            TechnologyRow.question(name: "Cribl Stream", components: 3).hasPrefix("3 components use")
        )
    }

    @Test func deletesTheTechnologyAndItsComponentsAsOneUndoableChange() throws {
        let (session, id) = withACustomTechnology()
        #expect(id.isEmpty == false)
        session.add(technologyId: id, x: 0, y: 0)
        #expect(session.canvas.components.count == 1)

        _ = session.deleteCustomTechnology(id)

        #expect(session.canvas.components.isEmpty)
        #expect(session.customTechnology(id) == nil)

        session.undo()

        // One undo puts the technology and its component back.
        #expect(session.canvas.components.count == 1)
        #expect(session.customTechnology(id) != nil)
    }
}

/// Drawing a zone is one undoable change.
@MainActor
@Suite("Taking back a zone")
struct ZoneUndoTests {
    private func session() -> ThreatModelSession {
        ThreatModelSession(useCases: TestDependencies())
    }

    @Test func oneUndoRemovesTheZoneAndNothingElse() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        #expect(session.canvas.components.count == 1)

        let zoneId = session.addZone(x: 0, y: 0, width: 400, height: 400)
        #expect(zoneId != nil)
        #expect(session.canvas.zones.count == 1)

        session.undo()

        #expect(session.canvas.zones.isEmpty)
        #expect(session.canvas.components.count == 1)
    }

    @Test func redoPutsTheZoneBackWithTheSameRectangle() throws {
        let session = session()
        _ = session.addZone(x: 10, y: 20, width: 400, height: 300)
        let drawn = try #require(session.canvas.zones.first)

        session.undo()
        session.redo()

        let again = try #require(session.canvas.zones.first)
        #expect(again.id == drawn.id)
        #expect(again.x == drawn.x)
        #expect(again.y == drawn.y)
        #expect(again.width == drawn.width)
        #expect(again.height == drawn.height)
        #expect(again.name == drawn.name)
    }

    /// Every use case one zone drag calls, and how many of them change the
    /// model. A second change is what made one undo leave the zone behind.
    @Test func oneZoneDragCallsOneChangingUseCase() {
        let useCases = TestDependencies()
        let session = ThreatModelSession(useCases: useCases)
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let before = useCases.modelStore.current()

        _ = session.addZone(x: 0, y: 0, width: 400, height: 400)

        // One undo returns the model to exactly what it was before the drag.
        session.undo()
        #expect(useCases.modelStore.current() == before)
    }

    /// The drag itself, the way the canvas runs it: start drawing, drag out a
    /// rectangle, end. One undo takes the whole drag back.
    @Test func oneZoneDragIsOneUndoableChange() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let canvas = CanvasState()
        let gestures = CanvasGestures(session: session, canvas: canvas)

        canvas.startDrawingZone()
        canvas.zoneDraft = (start: CGPoint(x: 0, y: 0), end: CGPoint(x: 400, y: 400))
        gestures.commitDraftZone()

        #expect(session.canvas.zones.count == 1)
        #expect(canvas.isDrawingZone == false)

        session.undo()

        #expect(session.canvas.zones.isEmpty)
        #expect(session.canvas.components.count == 1)
    }

    @Test func undoingAZoneLeavesTheComponentsItCoveredWhereTheyWere() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 100, y: 100)
        let placed = try #require(session.canvas.components.first)

        _ = session.addZone(x: 0, y: 0, width: 400, height: 400)
        session.undo()

        let after = try #require(session.canvas.components.first)
        #expect(after.id == placed.id)
        #expect(after.x == placed.x)
        #expect(after.y == placed.y)
    }
}

/// Which Cut, Copy and Paste a keystroke means.
@MainActor
@Suite("Routing the pasteboard by what holds the focus")
struct PasteboardRoutingTests {
    @Test func aTextFieldEditsItsText() {
        #expect(PasteboardRouting.target(isEditingText: true) == .textField)
    }

    @Test func anythingElseActsOnTheCanvas() {
        #expect(PasteboardRouting.target(isEditingText: false) == .canvas)
    }

    /// The canvas half of the routing: copying a selection puts the clipboard
    /// text on the pasteboard, and pasting puts the elements back.
    @Test func theCanvasCopiesAndPastesItsElements() throws {
        let session = ThreatModelSession(
            useCases: TestDependencies(),
            clipboard: FakeClipboard()
        )
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let placed = try #require(session.canvas.components.first)

        session.copySelection(componentIds: [placed.id], zoneIds: [])
        let pasted = session.paste()

        #expect(pasted.componentIds.count == 1)
        #expect(session.canvas.components.count == 2)
    }
}

/// The Edit menu names the change Undo would take back.
@MainActor
@Suite("What the Edit menu calls Undo")
struct UndoTitleTests {
    private func session() -> ThreatModelSession {
        ThreatModelSession(useCases: TestDependencies())
    }

    @Test func readsUndoAloneWhenTheHistoryIsEmpty() {
        let session = session()

        #expect(session.undoTitle == "Undo")
        #expect(session.redoTitle == "Redo")
    }

    @Test func namesTheChangeAfterAMove() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        #expect(session.undoTitle == "Undo Add Component")

        let placed = try #require(session.canvas.components.first)
        session.move([ComponentMove(componentId: placed.id, x: 80, y: 80)])

        #expect(session.undoTitle == "Undo Move")
    }

    @Test func namesTheChangeAfterAnUndoAndAfterARedo() {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)

        session.undo()
        #expect(session.undoTitle == "Undo")
        #expect(session.redoTitle == "Redo Add Component")

        session.redo()
        #expect(session.undoTitle == "Undo Add Component")
        #expect(session.redoTitle == "Redo")
    }
}

/// Renaming an element on the canvas, in place.
@MainActor
@Suite("Renaming on the canvas")
struct InlineRenameTests {
    private func session() -> ThreatModelSession {
        ThreatModelSession(useCases: TestDependencies())
    }

    @Test func renamesANodeAsOneChange() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let canvas = CanvasState()
        let gestures = CanvasGestures(session: session, canvas: canvas)
        let placed = try #require(session.canvas.components.first)

        canvas.startEditingName(.component(placed.id))
        #expect(canvas.isEditingName(.component(placed.id)))

        gestures.renameComponent(placed.id, to: "  Web tier  ")

        #expect(canvas.editingName == nil)
        #expect(try #require(session.canvas.components.first).name == "Web tier")

        session.undo()
        #expect(try #require(session.canvas.components.first).name != "Web tier")
    }

    @Test func renamesAZoneAsOneChange() throws {
        let session = session()
        _ = session.addZone(x: 0, y: 0, width: 400, height: 400)
        let canvas = CanvasState()
        let gestures = CanvasGestures(session: session, canvas: canvas)
        let drawn = try #require(session.canvas.zones.first)

        gestures.renameZone(drawn.id, to: "Payments VPC")

        #expect(try #require(session.canvas.zones.first).name == "Payments VPC")
        #expect(canvas.editingName == nil)

        session.undo()
        #expect(try #require(session.canvas.zones.first).name != "Payments VPC")
    }

    @Test func labelsAFlowAsOneChange() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])
        let flow = try #require(session.canvas.connections.first)
        let canvas = CanvasState()
        let gestures = CanvasGestures(session: session, canvas: canvas)

        canvas.startEditingName(.connection(flow.id))
        gestures.labelConnection(flow.id, to: "the card number")

        // One field, one value: the label is the description the panel edits.
        #expect(try #require(session.canvas.connections.first).description == "the card number")
        #expect(canvas.editingName == nil)

        session.undo()
        #expect(try #require(session.canvas.connections.first).description == nil)
    }

    @Test func changesNothingWhenTheNameIsUnchanged() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let canvas = CanvasState()
        let gestures = CanvasGestures(session: session, canvas: canvas)
        let placed = try #require(session.canvas.components.first)
        let revision = session.revision

        gestures.renameComponent(placed.id, to: placed.customName ?? "")

        #expect(session.revision == revision)
        #expect(canvas.editingName == nil)
    }

    @Test func reversesAFlowFromTheSession() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        let ids = session.canvas.components.map(\.id)
        session.connect(sourceComponentId: ids[0], targetComponentId: ids[1])
        let flow = try #require(session.canvas.connections.first)

        session.reverseConnection(flow.id)

        let reversed = try #require(session.canvas.connections.first)
        #expect(reversed.sourceComponentId == flow.targetComponentId)
        #expect(reversed.targetComponentId == flow.sourceComponentId)
    }
}
