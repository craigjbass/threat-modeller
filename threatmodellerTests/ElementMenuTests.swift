import CoreGraphics
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// What a secondary click offers, and what each item calls.
@MainActor
@Suite("The context menus")
struct ElementMenuTests {
    private func drawn() -> (ThreatModelSession, CanvasState, ElementMenu) {
        let session = ThreatModelSession(
            useCases: TestDependencies(),
            clipboard: FakeClipboard()
        )
        let canvas = CanvasState()
        return (session, canvas, ElementMenu(session: session, canvas: canvas))
    }

    private func twoNodes() -> (ThreatModelSession, CanvasState, ElementMenu, String, String) {
        let (session, canvas, menu) = drawn()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        let ids = session.canvas.components.map(\.id)
        return (session, canvas, menu, ids[0], ids[1])
    }

    private func identifiers(_ rows: [ElementMenu.Row]) -> [String] {
        rows.map(\.id)
    }

    private func run(_ rows: [ElementMenu.Row], _ id: String) {
        for row in rows {
            switch row {
            case .item(let rowId, _, _, _, let act) where rowId == id:
                act()
                return
            case .submenu(_, _, let children):
                if children.contains(where: { $0.id == id }) {
                    run(children, id)
                    return
                }
            default:
                continue
            }
        }
        Issue.record("no item called \(id)")
    }

    // MARK: the order of the rows

    @Test func theComponentMenuReadsInTheOrderWritten() {
        let (_, _, menu, api, _) = twoNodes()

        #expect(
            identifiers(menu.component(api)) == [
                "context-component-rename",
                "context-component-show-threats",
                "context-component-show-controls",
                "context-component-focus",
                "context-component-separator-1",
                "context-component-raise-threats",
                "context-component-sensitivity",
                "context-component-runs-as",
                "context-component-connect-to",
                "context-component-separator-2",
                "context-component-cut",
                "context-component-copy",
                "context-component-duplicate",
                "context-component-separator-3",
                "context-component-delete"
            ]
        )
    }

    @Test func theZoneMenuReadsInTheOrderWritten() throws {
        let (session, _, menu) = drawn()
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 400, height: 300))

        #expect(
            identifiers(menu.zone(zoneId)) == [
                "context-zone-rename",
                "context-zone-show-threats",
                "context-zone-show-controls",
                "context-zone-separator-1",
                "context-zone-kind",
                "context-zone-select-contents",
                "context-zone-separator-2",
                "context-zone-cut",
                "context-zone-copy",
                "context-zone-duplicate",
                "context-zone-separator-3",
                "context-zone-delete"
            ]
        )
    }

    @Test func theConnectionMenuReadsInTheOrderWritten() throws {
        let (session, _, menu, api, db) = twoNodes()
        session.connect(sourceComponentId: api, targetComponentId: db)
        let flow = try #require(session.canvas.connections.first)

        #expect(
            identifiers(menu.connection(flow.id)) == [
                "context-connection-label",
                "context-connection-show-threats",
                "context-connection-separator-1",
                "context-connection-kind",
                "context-connection-separator-2",
                "context-connection-delete"
            ]
        )
    }

    @Test func theCanvasMenuReadsInTheOrderWritten() {
        let (_, _, menu) = drawn()

        #expect(
            identifiers(menu.background(at: .zero)) == [
                "context-canvas-paste",
                "context-canvas-select-all",
                "context-canvas-separator-1",
                "context-canvas-draw-zone"
            ]
        )
    }

    // MARK: what a secondary click selects

    @Test func aClickOnSomethingUnselectedSelectsItAlone() {
        let (_, canvas, menu, api, db) = twoNodes()
        canvas.select(componentId: db, addingToSelection: false)

        menu.selectBeforeMenu(componentId: api)

        #expect(canvas.selectedComponentIds == [api])
    }

    @Test func aClickOnSomethingSelectedKeepsTheWholeSelection() {
        let (_, canvas, menu, api, db) = twoNodes()
        canvas.select(componentId: api, addingToSelection: false)
        canvas.select(componentId: db, addingToSelection: true)

        menu.selectBeforeMenu(componentId: api)

        #expect(canvas.selectedComponentIds == [api, db])
    }

    // MARK: what each item calls

    @Test func renameOpensTheFieldOnTheNode() {
        let (_, canvas, menu, api, _) = twoNodes()

        run(menu.component(api), "context-component-rename")

        #expect(canvas.isEditingName(.component(api)))
    }

    @Test func labelOpensTheFieldOnTheFlow() throws {
        let (session, canvas, menu, api, db) = twoNodes()
        session.connect(sourceComponentId: api, targetComponentId: db)
        let flow = try #require(session.canvas.connections.first)

        run(menu.connection(flow.id), "context-connection-label")

        #expect(canvas.isEditingName(.connection(flow.id)))
    }

    @Test func showThreatsChangesTheStageAndFocusesTheElement() {
        let (session, canvas, menu, api, _) = twoNodes()
        var asked: WorkStage?
        canvas.showStage = { asked = $0 }

        run(menu.component(api), "context-component-show-threats")

        #expect(asked == .threats)
        #expect(session.focusedElementId == "component:\(api)")
    }

    @Test func focusSetsTheFocusedComponent() {
        let (_, canvas, menu, api, _) = twoNodes()

        run(menu.component(api), "context-component-focus")

        #expect(canvas.focusedComponentId == api)
    }

    @Test func showControlsChangesTheStageAndOpensTheGroup() {
        let (session, canvas, menu, api, _) = twoNodes()
        session.collapseEveryGroup(["component:\(api)"])
        var asked: WorkStage?
        canvas.showStage = { asked = $0 }

        run(menu.component(api), "context-component-show-controls")

        #expect(asked == .controls)
        #expect(session.collapsedGroups.contains("component:\(api)") == false)
    }

    @Test func sensitivityWritesThroughTheSameVerbAsThePanel() {
        let (session, _, menu, api, _) = twoNodes()

        run(menu.component(api), "context-component-sensitivity-restricted")

        #expect(session.canvas.components.first { $0.id == api }?.sensitivityId == "restricted")
    }

    @Test func runsAsWritesThroughTheSameVerbAsThePanel() {
        let (session, _, menu, api, _) = twoNodes()

        run(menu.component(api), "context-component-runs-as-root")

        #expect(session.canvas.components.first { $0.id == api }?.runsAsId == "root")
    }

    @Test func raiseThreatsTurnsTheThreatsOffAndTheItemStatesIt() {
        let (session, _, menu, api, _) = twoNodes()

        run(menu.component(api), "context-component-raise-threats")

        #expect(session.canvas.components.first { $0.id == api }?.threatsDisabled == true)
        let again = menu.component(api)
        #expect(again.first { $0.id == "context-component-raise-threats" }?.title == "Raise Threats")
    }

    @Test func connectToDrawsAFlowToThatComponent() {
        let (session, _, menu, api, db) = twoNodes()

        run(menu.component(api), "context-component-connect-to-\(db)")

        #expect(session.canvas.connections.first?.sourceComponentId == api)
        #expect(session.canvas.connections.first?.targetComponentId == db)
    }

    @Test func theConnectToSubmenuNamesEveryOtherComponent() {
        let (_, _, menu, api, db) = twoNodes()

        let rows = menu.component(api)
        guard case .submenu(_, _, let others) = rows.first(where: {
            $0.id == "context-component-connect-to"
        }) else {
            Issue.record("the menu offers no Connect To")
            return
        }

        #expect(identifiers(others) == ["context-component-connect-to-\(db)"])
    }

    @Test func cutCopyAndDuplicateActOnTheWholeSelection() {
        let (session, canvas, menu, api, db) = twoNodes()
        canvas.select(componentId: api, addingToSelection: false)
        canvas.select(componentId: db, addingToSelection: true)

        run(menu.component(api), "context-component-duplicate")

        #expect(session.canvas.components.count == 4)
        #expect(canvas.selectedComponentIds.count == 2)
    }

    @Test func deleteActsOnTheWholeSelection() {
        let (session, canvas, menu, api, db) = twoNodes()
        canvas.select(componentId: api, addingToSelection: false)
        canvas.select(componentId: db, addingToSelection: true)

        run(menu.component(api), "context-component-delete")

        #expect(session.canvas.components.isEmpty)
    }

    @Test func everyChangeFromAMenuIsOneUndo() {
        let (session, _, menu, api, _) = twoNodes()

        run(menu.component(api), "context-component-sensitivity-restricted")
        #expect(session.undoTitle == "Undo Edit Component")
        session.undo()

        #expect(session.canvas.components.first { $0.id == api }?.sensitivityId != "restricted")
    }

    @Test func zoneKindWritesThroughTheSameVerbAsThePanel() throws {
        let (session, _, menu) = drawn()
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 400, height: 300))

        run(menu.zone(zoneId), "context-zone-kind-public")

        #expect(session.canvas.zones.first?.networkZoneId == "public")
    }

    @Test func selectContentsSelectsEveryComponentInTheZone() throws {
        let (session, canvas, menu) = drawn()
        session.add(technologyId: "aws-ec2", x: 40, y: 40)
        let zoneId = try #require(session.addZone(x: 0, y: 0, width: 400, height: 300))
        let inside = try #require(session.canvas.components.first)

        run(menu.zone(zoneId), "context-zone-select-contents")

        #expect(canvas.selectedComponentIds == [inside.id])
    }

    /// A zone that holds nothing still offers Select Contents, off.
    @Test func selectContentsIsOffForAnEmptyZone() throws {
        let (session, _, menu) = drawn()
        let zoneId = try #require(session.addZone(x: 2000, y: 2000, width: 400, height: 300))

        let rows = menu.zone(zoneId)
        guard case .item(_, _, _, let isEnabled, _) = try #require(
            rows.first { $0.id == "context-zone-select-contents" }
        ) else {
            Issue.record("the menu offers no Select Contents")
            return
        }

        #expect(isEnabled == false)
    }

    @Test func flowKindWritesThroughTheSameVerbAsThePanel() throws {
        let (session, _, menu, api, db) = twoNodes()
        session.connect(sourceComponentId: api, targetComponentId: db)
        let flow = try #require(session.canvas.connections.first)

        run(menu.connection(flow.id), "context-connection-kind-ipc")

        #expect(session.canvas.connections.first?.kindId == "ipc")
    }

    @Test func drawZoneStartsWhereTheClickLanded() {
        let (_, canvas, menu) = drawn()

        run(menu.background(at: CGPoint(x: 120, y: 90)), "context-canvas-draw-zone")

        #expect(canvas.isDrawingZone)
        #expect(canvas.zoneDraftRect == CGRect(x: 120, y: 90, width: 0, height: 0))
    }

    @Test func selectAllFromTheCanvasMenuSelectsEverything() throws {
        let (session, canvas, menu) = drawn()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        _ = session.addZone(x: 0, y: 0, width: 400, height: 300)

        run(menu.background(at: .zero), "context-canvas-select-all")

        #expect(canvas.selectedComponentIds.count == 1)
        #expect(canvas.selectedZoneIds.count == 1)
    }

    @Test func pasteFromTheCanvasMenuPutsTheCopyBack() {
        let (session, canvas, menu, api, _) = twoNodes()
        session.copySelection(componentIds: [api], zoneIds: [])

        run(menu.background(at: .zero), "context-canvas-paste")

        #expect(session.canvas.components.count == 3)
        #expect(canvas.selectedComponentIds.count == 1)
    }

    /// A component whose threats are off still offers Show Threats, and the
    /// sidebar then draws that element's group with nothing in it.
    @Test func showThreatsIsThereForAComponentThatRaisesNone() {
        let (session, canvas, menu, api, _) = twoNodes()
        run(menu.component(api), "context-component-raise-threats")
        canvas.showStage = { _ in }

        run(menu.component(api), "context-component-show-threats")

        #expect(session.focusedElementId == "component:\(api)")
        #expect(session.threats.contains { $0.source.id == "component:\(api)" } == false)
    }
}
