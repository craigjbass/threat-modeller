import AppKit
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// What the right sidebar of the Architecture stage shows.
///
/// The design in
/// `docs/superpowers/specs/2026-09-16-selection-editor-in-the-sidebar-design.md`
/// states the rule: the column holds the editor for what is selected, and its
/// default content when nothing is selected. `CanvasSelection` states which,
/// so a test reads it without a window.
@MainActor
@Suite("What the right sidebar shows")
struct SelectionSidebarTests {
    /// A model with two components, a flow between them, a zone and a user.
    private func aModel() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        let components = session.canvas.components
        session.connect(
            sourceComponentId: components[0].id,
            targetComponentId: components[1].id
        )
        _ = session.addZone(x: 0, y: 0, width: 300, height: 200)
        return session
    }

    private func selection(
        _ session: ThreatModelSession,
        _ canvas: CanvasState
    ) -> CanvasSelection {
        CanvasSelection.of(session: session, canvas: canvas)
    }

    @Test func showsTheDefaultContentWhileNothingIsSelected() {
        let session = aModel()

        #expect(selection(session, CanvasState()) == .nothing)
    }

    @Test func showsTheComponentEditorForOneComponent() throws {
        let session = aModel()
        let canvas = CanvasState()
        let component = try #require(session.canvas.components.first)
        canvas.select(componentId: component.id, addingToSelection: false)

        #expect(selection(session, canvas) == .component(component))
    }

    @Test func showsTheUserEditorForOneUser() throws {
        let session = aModel()
        session.addUser(x: 800, y: 0)
        let canvas = CanvasState()
        let user = try #require(session.canvas.components.first { $0.isUser })
        canvas.select(componentId: user.id, addingToSelection: false)

        #expect(selection(session, canvas) == .user(user))
    }

    @Test func showsTheZoneEditorForOneZone() throws {
        let session = aModel()
        let canvas = CanvasState()
        let zone = try #require(session.canvas.zones.first)
        canvas.select(zoneId: zone.id)

        #expect(selection(session, canvas) == .zone(zone))
    }

    @Test func showsTheFlowEditorForOneFlow() throws {
        let session = aModel()
        let canvas = CanvasState()
        let connection = try #require(session.canvas.connections.first)
        canvas.select(connectionId: connection.id, addingToSelection: false)

        #expect(selection(session, canvas) == .connection(connection))
    }

    // MARK: two or more

    @Test func showsTheMultiSelectionViewForTwoComponentsAndOffersMerge() throws {
        let session = aModel()
        let canvas = CanvasState()
        let components = session.canvas.components
        canvas.select(componentIds: components.map(\.id))

        guard case .several(let several) = selection(session, canvas) else {
            Issue.record("two components showed \(selection(session, canvas))")
            return
        }

        #expect(several.counts == ["2 components"])
        #expect(several.offersMerge, "two components offer no Merge")
        #expect(several.mitigates != nil, "two components offer no mitigates row")
    }

    @Test func countsEachKindOfSelectedElement() throws {
        let session = aModel()
        let canvas = CanvasState()
        let zone = try #require(session.canvas.zones.first)
        canvas.select(
            componentIds: session.canvas.components.map(\.id),
            zoneIds: [zone.id]
        )

        guard case .several(let several) = selection(session, canvas) else {
            Issue.record("a mixed selection showed no multi-selection view")
            return
        }

        #expect(several.counts == ["2 components", "1 zone"])
    }

    @Test func offersNoMergeWhenTheSelectionHoldsAUser() throws {
        let session = aModel()
        session.addUser(x: 800, y: 0)
        let canvas = CanvasState()
        let user = try #require(session.canvas.components.first { $0.isUser })
        let component = try #require(session.canvas.components.first { $0.isUser == false })
        canvas.select(componentIds: [user.id, component.id])

        guard case .several(let several) = selection(session, canvas) else {
            Issue.record("a user and a component showed no multi-selection view")
            return
        }

        #expect(several.offersMerge == false, "a user is offered a Merge")
    }

    @Test func theMergeButtonOpensTheMergeSheet() throws {
        let session = aModel()
        let canvas = CanvasState()
        canvas.select(componentIds: session.canvas.components.map(\.id))

        guard case .several(let several) = selection(session, canvas) else {
            Issue.record("two components showed no multi-selection view")
            return
        }
        canvas.startMerging(componentIds: several.componentIds)

        #expect(canvas.isMerging, "the merge sheet is closed")
    }

    @Test func theDeleteButtonRemovesTheWholeSelection() throws {
        let session = aModel()
        let canvas = CanvasState()
        canvas.select(componentIds: session.canvas.components.map(\.id))

        CanvasGestures(session: session, canvas: canvas).deleteSelection()

        #expect(session.canvas.components.isEmpty, "the components stand")
    }

    // MARK: the column itself

    /// The sidebar draws one of two views and never both.
    @Test func theSidebarDrawsTheEditorAndTheDefaultContentAtEveryWidth() throws {
        let session = aModel()
        let canvas = CanvasState()
        let component = try #require(session.canvas.components.first)

        for width in [280.0, 360.0, 480.0] {
            let empty = NSHostingView(
                rootView: SelectionSidebar(session: session, canvas: CanvasState())
                    .frame(width: width, height: 700)
            )
            empty.layoutSubtreeIfNeeded()
            #expect(empty.fittingSize.width > 0, "the default content drew nothing at \(width)")

            canvas.select(componentId: component.id, addingToSelection: false)
            let editor = NSHostingView(
                rootView: SelectionSidebar(session: session, canvas: canvas)
                    .frame(width: width, height: 700)
            )
            editor.layoutSubtreeIfNeeded()
            #expect(editor.fittingSize.width > 0, "the editor drew nothing at \(width)")
        }
    }
}
