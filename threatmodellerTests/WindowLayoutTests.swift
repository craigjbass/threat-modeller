import AppKit
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Where the project window puts its parts, measured in a real window.
///
/// `ImageRenderer` draws a view but tells nothing about what covers what. These
/// tests put the window in an `NSWindow`, let AppKit lay it out, and read the
/// frames back.
@MainActor
struct WindowLayoutTests {
    private static let width = 1200.0
    private static let height = 800.0

    private func aDrawnProject() async -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        let session = ProjectSession(useCases: useCases, watcher: FakeProjectWatcher(), defaults: aTestDefaults())
        await session.open(root: "/work")
        return session
    }

    /// A project with two components and a flow, so every selection panel has
    /// something to show.
    private func aFlowProject() async -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }
              component "db" {
                technology = "aws-rds"
                data       = "confidential"
              }
              flow api -> db
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        let session = ProjectSession(useCases: useCases, watcher: FakeProjectWatcher(), defaults: aTestDefaults())
        await session.open(root: "/work")
        return session
    }

    /// A window holding the view, laid out.
    private func laidOut(_ view: some View) -> NSWindow {
        let hosting = NSHostingView(rootView: view)
        hosting.frame = NSRect(x: 0, y: 0, width: Self.width, height: Self.height)
        let window = NSWindow(
            contentRect: hosting.frame,
            styleMask: [.titled, .closable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.contentView = hosting
        hosting.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(1))
        hosting.layoutSubtreeIfNeeded()
        return window
    }

    /// The split view holding the three columns.
    private func columns(in view: NSView) -> NSSplitView? {
        if let split = view as? NSSplitView { return split }
        for child in view.subviews {
            if let split = columns(in: child) { return split }
        }
        return nil
    }

    /// Every view drawn outside the columns, as one rectangle in window
    /// coordinates. That is the chrome: the workflow bar and the notices under
    /// it.
    private func chrome(in view: NSView, outside columns: NSSplitView) -> NSRect? {
        if view === columns { return nil }

        var rectangle: NSRect?
        for child in view.subviews {
            guard let found = chrome(in: child, outside: columns) else { continue }
            rectangle = rectangle.map { $0.union(found) } ?? found
        }
        if rectangle != nil { return rectangle }

        let own = view.convert(view.bounds, to: nil)
        guard view.subviews.isEmpty, own.width > 0, own.height > 0 else { return nil }
        return own
    }

    /// The workflow bar sits above the columns, not over them.
    ///
    /// `safeAreaInset` does not inset a `NavigationSplitView` on macOS: the
    /// columns still take the whole window, so a bar drawn that way covers the
    /// top of the palette and of the threat sidebar, and no scroll brings that
    /// top back into view.
    @Test func keepsTheNoticesAboveTheColumns() async throws {
        let window = laidOut(ProjectWindow(session: await aDrawnProject()))
        let content = try #require(window.contentView)
        let columns = try #require(self.columns(in: content))
        let bar = chrome(in: content, outside: columns)

        // With no notice to show there is no chrome at all, which is the
        // point of the floating panel: the columns take the whole window.
        if let bar {
            let columnsTop = columns.convert(columns.bounds, to: nil).maxY
            #expect(
                bar.minY >= columnsTop,
                "the chrome sits at \(bar.minY)…\(bar.maxY) and the columns reach \(columnsTop)"
            )
        }
    }

    /// The floating panel sits above whichever selection panel is shown, so
    /// the two never cover each other. Each panel is measured at the width the
    /// canvas column has.
    @Test func theFloatingPanelNeverCoversASelectionPanel() async throws {
        let model = ThreatModelSession(useCases: TestDependencies())
        model.add(technologyId: "aws-ec2", x: 0, y: 0)
        model.add(technologyId: "aws-rds", x: 400, y: 0)
        let components = model.canvas.components
        model.connect(
            sourceComponentId: components[0].id,
            targetComponentId: components[1].id
        )
        let connection = try #require(model.canvas.connections.first)
        _ = model.addZone(x: 0, y: 0, width: 400, height: 300)
        let zone = try #require(model.canvas.zones.first)

        let panels: [(String, AnyView)] = [
            ("component", AnyView(ComponentPanel(session: model, component: components[0]))),
            ("zone", AnyView(ZonePanel(session: model, zone: zone))),
            ("connection", AnyView(ConnectionPanel(session: model, connection: connection))),
            (
                "mitigates",
                AnyView(
                    MitigatesPanel(
                        session: model,
                        source: components[0],
                        target: components[1]
                    )
                )
            )
        ]

        let column = CGRect(x: 0, y: 0, width: 700, height: 800)
        let project = await aDrawnProject()
        let floating = NSHostingView(
            rootView: WorkflowPanel(session: project, stage: .constant(.architecture))
        ).fittingSize

        for (name, panel) in panels {
            let hosting = NSHostingView(rootView: panel)
            hosting.frame = NSRect(x: 0, y: 0, width: column.width, height: 0)
            let height = hosting.fittingSize.height
            #expect(height > 0, "the \(name) panel measured no height")

            let selection = WorkflowPanel.selectionPanelRect(in: column, height: height)
            let above = WorkflowPanel.rect(in: column, panelSize: floating, liftedBy: height)

            #expect(
                above.intersects(selection) == false,
                "the floating panel at \(above) covers the \(name) panel at \(selection)"
            )
            #expect(
                selection.minY - above.maxY == WorkflowPanel.gapAboveSelectionPanel,
                "the gap above the \(name) panel is \(selection.minY - above.maxY)"
            )
        }

        // With no selection panel the floating panel returns to the margin.
        let alone = WorkflowPanel.rect(in: column, panelSize: floating, liftedBy: 0)
        #expect(column.maxY - alone.maxY == WorkflowPanel.bottomMargin)
    }

    /// The threats stage draws the diagram on the left and the threat list on
    /// the right, each reaching its own edge of the window, and the two never
    /// overlap.
    @Test func drawsTheDiagramAndTheThreatListSideBySideOnTheThreatsStage() async throws {
        let project = await aDrawnProject()
        let model = try #require(project.model)
        let window = laidOut(
            ProjectColumns(
                project: project,
                session: model,
                canvas: CanvasState(),
                stage: .constant(.threats)
            )
        )
        let content = try #require(window.contentView)
        let split = try #require(columns(in: content))
        #expect(split.arrangedSubviews.count == 2)

        let left = split.arrangedSubviews[0].convert(split.arrangedSubviews[0].bounds, to: nil)
        let right = split.arrangedSubviews[1].convert(split.arrangedSubviews[1].bounds, to: nil)
        let whole = content.convert(content.bounds, to: nil)

        #expect(left.minX == whole.minX)
        #expect(right.maxX == whole.maxX)
        #expect(left.intersects(right) == false)
        #expect(left.width >= ProjectColumns.minimumDiagramWidth)
        #expect(right.width >= ProjectColumns.minimumThreatListWidth)
    }

    /// The person drags the divider, and neither side goes below its stated
    /// minimum.
    @Test func theThreatsStageDividerHoldsEachSideAtItsMinimum() async throws {
        let project = await aDrawnProject()
        let model = try #require(project.model)
        let window = laidOut(
            ProjectColumns(
                project: project,
                session: model,
                canvas: CanvasState(),
                stage: .constant(.threats)
            )
        )
        let content = try #require(window.contentView)
        let split = try #require(columns(in: content))

        // Drag the divider as far left as it goes.
        split.setPosition(0, ofDividerAt: 0)
        split.layoutSubtreeIfNeeded()

        let left = split.arrangedSubviews[0].frame.width
        #expect(left >= ProjectColumns.minimumDiagramWidth)
    }

    /// The canvas keeps room under it for the panel, so a node at the bottom
    /// of the model is never hidden by it.
    @Test func theCanvasKeepsRoomUnderItForTheFloatingPanel() async throws {
        let project = await aDrawnProject()
        let floating = NSHostingView(
            rootView: WorkflowPanel(session: project, stage: .constant(.architecture))
        ).fittingSize

        #expect(WorkflowPanel.reservedHeight >= floating.height)
    }

    /// The columns never cover the selection panel. Each panel scrolls its
    /// controls inside the canvas column, so nothing draws under the
    /// assumptions column, even when the closed palette leaves the canvas
    /// narrow and the selected element's row is wider than the column.
    @Test func theColumnsNeverCoverTheSelectionPanel() async throws {
        let project = await aFlowProject()
        project.paletteColumns = .doubleColumn
        let model = try #require(project.model)
        let components = model.canvas.components
        _ = model.addZone(x: 0, y: 0, width: 200, height: 150)
        let zone = try #require(model.canvas.zones.first)
        let connection = try #require(model.canvas.connections.first)

        let selections: [(String, (CanvasState) -> Void)] = [
            ("component", { $0.select(componentId: components[0].id, addingToSelection: false) }),
            ("connection", { $0.select(connectionId: connection.id, addingToSelection: false) }),
            ("zone", { $0.select(componentIds: [], zoneIds: [zone.id]) }),
            ("mitigates", { $0.select(componentIds: [components[0].id, components[1].id]) })
        ]

        for (name, select) in selections {
            let canvas = CanvasState()
            select(canvas)
            let window = laidOut(
                ProjectColumns(
                    project: project,
                    session: model,
                    canvas: canvas,
                    stage: .constant(.architecture)
                ),
                width: 940
            )
            let content = try #require(window.contentView)
            let split = try #require(columns(in: content))
            let pane = split.arrangedSubviews[1].convert(
                split.arrangedSubviews[1].bounds, to: nil
            )
            let detail = split.arrangedSubviews[2].convert(
                split.arrangedSubviews[2].bounds, to: nil
            )
            let panelView = try #require(
                selectionPanel(in: split.arrangedSubviews[1]),
                "no \(name) panel in the canvas column"
            )
            let panel = panelView.convert(panelView.bounds, to: nil)

            #expect(panel.width > 0, "the \(name) panel measured no width")
            #expect(
                panel.maxX <= pane.maxX + 0.5,
                "the \(name) panel at \(panel) leaves its column \(pane)"
            )
            #expect(
                panel.intersects(detail) == false,
                "the assumptions column at \(detail) covers the \(name) panel at \(panel)"
            )
        }
    }

    /// Closing the palette widens the canvas, not the assumptions: the detail
    /// column stops at its stated cap.
    @Test func closingThePaletteWidensTheCanvasNotTheAssumptions() async throws {
        let project = await aFlowProject()
        project.paletteColumns = .doubleColumn
        let model = try #require(project.model)
        let window = laidOut(
            ProjectColumns(
                project: project,
                session: model,
                canvas: CanvasState(),
                stage: .constant(.architecture)
            ),
            width: 1200
        )
        let content = try #require(window.contentView)
        let split = try #require(columns(in: content))
        let canvasPane = split.arrangedSubviews[1].frame.width
        let detailPane = split.arrangedSubviews[2].frame.width

        #expect(detailPane <= 480, "the assumptions column took \(detailPane)")
        #expect(canvasPane >= 700, "the canvas got \(canvasPane) of 1200")
    }

    /// A project whose component states a tag, so the canvas toolbar draws
    /// its tag filter menu. That menu is an AppKit control, so a test reads
    /// its frame back and with it the trailing edge of the toolbar row.
    private func aTaggedProject() async -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
                tags       = ["payments"]
              }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        let session = ProjectSession(useCases: useCases, watcher: FakeProjectWatcher(), defaults: aTestDefaults())
        await session.open(root: "/work")
        return session
    }

    /// Drags the divider and lets AppKit lay the columns out again.
    private func moveDivider(_ split: NSSplitView, to position: Double) {
        split.setPosition(position, ofDividerAt: 0)
        split.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.4))
        split.layoutSubtreeIfNeeded()
    }

    /// Every view under this one that takes a drop, in window coordinates.
    /// The canvas takes a technology and the workflow panel stops one, so the
    /// two are the drop takers the diagram column holds.
    private func dropTakers(in view: NSView, into found: inout [NSRect]) {
        if view.registeredDraggedTypes.isEmpty == false {
            found.append(view.convert(view.bounds, to: nil))
        }
        for child in view.subviews { dropTakers(in: child, into: &found) }
    }

    /// Every pop-up button under this one, in window coordinates.
    private func popUpButtons(in view: NSView, into found: inout [NSRect]) {
        if view is NSPopUpButton {
            found.append(view.convert(view.bounds, to: nil))
        }
        for child in view.subviews { popUpButtons(in: child, into: &found) }
    }

    /// The panel fits every column width the split allows.
    ///
    /// The panel drops words as the column narrows. This states, for each
    /// width, that what the panel then measures fits inside the column, so a
    /// threshold that is set too low fails here rather than on screen.
    @Test func theWorkflowPanelFitsEveryColumnWidthTheSplitAllows() async throws {
        let project = await aDrawnProject()
        let model = try #require(project.model)
        let canvas = CanvasState()

        for width in [
            ProjectColumns.minimumDiagramWidth,
            480.0,
            WorkflowPanel.stageWordsWidth,
            640.0,
            WorkflowPanel.allWordsWidth,
            900.0,
            1080.0
        ] {
            let hosting = NSHostingView(
                rootView: WorkflowPanel(
                    session: project,
                    stage: .constant(.threats),
                    canvas: canvas,
                    model: model,
                    columnWidth: width
                )
            )
            let measured = hosting.fittingSize.width
            #expect(
                measured <= width,
                "the panel needs \(measured) in a column of \(width)"
            )
        }
    }

    /// The controls that float over the diagram follow the diagram column.
    ///
    /// The person drags the divider of the threats stage. The canvas toolbar,
    /// the workflow panel and the selection panel each have to fit the column
    /// at its new width, so none of them draws over the threat sidebar.
    @Test func theFloatingControlsFitTheDiagramColumnAtEveryDividerPosition() async throws {
        let project = await aTaggedProject()
        let model = try #require(project.model)
        let canvas = CanvasState()
        canvas.select(componentId: model.canvas.components[0].id, addingToSelection: false)
        let window = laidOut(
            ProjectColumns(
                project: project,
                session: model,
                canvas: canvas,
                stage: .constant(.threats)
            ),
            width: 1400
        )
        let content = try #require(window.contentView)
        let split = try #require(columns(in: content))

        // The widest the divider goes, the middle, and the narrowest the
        // split allows.
        for position in [1080.0, 700.0, 0.0] {
            moveDivider(split, to: position)
            let pane = split.arrangedSubviews[0]
            let column = pane.convert(pane.bounds, to: nil)
            let sidebarView = split.arrangedSubviews[1]
            let sidebar = sidebarView.convert(sidebarView.bounds, to: nil)

            var takers: [NSRect] = []
            dropTakers(in: pane, into: &takers)
            // The canvas is the tall one and the workflow panel the short one.
            let sorted = takers.sorted { $0.height < $1.height }
            let panel = try #require(sorted.first, "no workflow panel at \(column.width)")
            let drawing = try #require(sorted.last, "no canvas at \(column.width)")

            var popUps: [NSRect] = []
            popUpButtons(in: pane, into: &popUps)
            // The canvas toolbar sits at the top of the column, so its tag
            // filter menu is the highest pop-up button in the column. It ends
            // the toolbar row, so its trailing edge is the row's.
            let toolbar = try #require(
                popUps.max(by: { $0.maxY < $1.maxY }),
                "no tag filter menu at \(column.width)"
            )

            let selectionView = try #require(
                selectionPanel(in: pane),
                "no selection panel at \(column.width)"
            )
            let selection = selectionView.convert(selectionView.bounds, to: nil)

            #expect(
                column.minX <= toolbar.minX && toolbar.maxX <= column.maxX,
                "the canvas toolbar at \(toolbar) leaves the column \(column)"
            )
            #expect(
                toolbar.intersects(sidebar) == false,
                "the canvas toolbar at \(toolbar) covers the threat sidebar at \(sidebar)"
            )
            #expect(
                column.minX <= panel.minX && panel.maxX <= column.maxX,
                "the workflow panel at \(panel) leaves the column \(column)"
            )
            #expect(
                panel.intersects(sidebar) == false,
                "the workflow panel at \(panel) covers the threat sidebar at \(sidebar)"
            )
            // The panel stays centred on the column it floats over.
            #expect(
                abs(panel.midX - column.midX) <= 1,
                "the workflow panel at \(panel) is off centre in \(column)"
            )
            #expect(
                column.minX <= selection.minX && selection.maxX <= column.maxX,
                "the selection panel at \(selection) leaves the column \(column)"
            )
            #expect(
                selection.intersects(sidebar) == false,
                "the selection panel at \(selection) covers the threat sidebar at \(sidebar)"
            )
            #expect(
                abs(drawing.width - column.width) <= 1,
                "the canvas is \(drawing.width) wide in a column of \(column.width)"
            )
        }
    }

    /// The Controls stage draws no selection panel, so the floating panel
    /// keeps the plain margin there, even after a component stays selected on
    /// the Architecture stage. Switching back to Architecture lifts the panel
    /// over the selection panel again.
    @Test func theFloatingPanelDropsItsLiftOnTheControlsStage() async throws {
        let project = await aFlowProject()
        let model = try #require(project.model)
        let canvas = CanvasState()
        canvas.select(componentId: model.canvas.components[0].id, addingToSelection: false)

        // Architecture, with a component selected: the canvas measures the
        // selection panel and writes its height onto the canvas.
        _ = laidOut(
            ProjectColumns(
                project: project,
                session: model,
                canvas: canvas,
                stage: .constant(.architecture)
            )
        )
        #expect(canvas.selectionPanelHeight > 0, "the selection panel measured no height")

        // Controls, with the same canvas: the stage draws no selection panel,
        // so the floating panel keeps the plain margin.
        let controlsWindow = laidOut(
            ProjectColumns(
                project: project,
                session: model,
                canvas: canvas,
                stage: .constant(.controls)
            )
        )
        let controlsContent = try #require(controlsWindow.contentView)
        var controlsTakers: [NSRect] = []
        dropTakers(in: controlsContent, into: &controlsTakers)
        let controlsPanel = try #require(
            controlsTakers.first, "no workflow panel on the Controls stage"
        )
        let controlsColumn = controlsContent.convert(controlsContent.bounds, to: nil)

        #expect(
            abs((controlsPanel.minY - controlsColumn.minY) - WorkflowPanel.bottomMargin) < 0.5,
            "the panel sits \(controlsPanel.minY - controlsColumn.minY) above the bottom on the Controls stage"
        )

        // Back on Architecture, with the same canvas: the panel lifts over
        // the selection panel again.
        let architectureWindow = laidOut(
            ProjectColumns(
                project: project,
                session: model,
                canvas: canvas,
                stage: .constant(.architecture)
            )
        )
        let architectureContent = try #require(architectureWindow.contentView)
        var architectureTakers: [NSRect] = []
        dropTakers(in: architectureContent, into: &architectureTakers)
        // The canvas is the tall one and the workflow panel the short one.
        let architecturePanel = try #require(
            architectureTakers.sorted(by: { $0.height < $1.height }).first,
            "no workflow panel on the Architecture stage"
        )
        let architectureColumn = architectureContent.convert(architectureContent.bounds, to: nil)

        #expect(
            architecturePanel.minY - architectureColumn.minY > WorkflowPanel.bottomMargin,
            "the panel sits at the plain margin on the Architecture stage with a selection shown"
        )
    }

    /// The selection panel: the one scroller the canvas column holds.
    private func selectionPanel(in view: NSView) -> NSScrollView? {
        if let scroll = view as? NSScrollView { return scroll }
        for child in view.subviews {
            if let found = selectionPanel(in: child) { return found }
        }
        return nil
    }

    private func laidOut(_ view: some View, width: Double) -> NSWindow {
        let hosting = NSHostingView(rootView: view)
        hosting.frame = NSRect(x: 0, y: 0, width: width, height: 700)
        let window = NSWindow(
            contentRect: hosting.frame,
            styleMask: [.titled, .closable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        window.contentView = hosting
        hosting.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(1))
        hosting.layoutSubtreeIfNeeded()
        return window
    }

}
