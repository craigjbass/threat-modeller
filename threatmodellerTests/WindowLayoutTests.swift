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

    /// #146: the checkbox toggle draws no trailing inset of its own, so the
    /// gap before the pointer picker needs a real view between them, not
    /// the toolbar's own item spacing, which a control with no bezel does
    /// not reserve any room against.
    @Test func theAutoSyncToggleHasAGapBeforeThePointerPicker() async throws {
        let window = laidOut(ProjectWindow(session: await aDrawnProject()))
        let toolbar = try #require(window.toolbar)

        var settingsItemView: NSView?
        for item in toolbar.items {
            guard let view = item.view else { continue }
            var popUps: [NSRect] = []
            popUpButtons(in: view, into: &popUps)
            var checkboxes: [NSRect] = []
            checkboxButtons(in: view, into: &checkboxes)
            if popUps.isEmpty == false, checkboxes.isEmpty == false {
                settingsItemView = view
            }
        }
        let itemView = try #require(
            settingsItemView,
            "no toolbar item holds both the Auto Sync toggle and the Pointer picker"
        )

        var popUps: [NSRect] = []
        popUpButtons(in: itemView, into: &popUps)
        let picker = try #require(popUps.first, "no pointer picker in the settings item")

        var leaves: [NSRect] = []
        leafViews(in: itemView, into: &leaves)
        let toggleTrailingEdge = try #require(
            leaves.filter { $0.maxX <= picker.minX + 0.5 }.map(\.maxX).max(),
            "no toggle content sits before the picker"
        )

        let gap = picker.minX - toggleTrailingEdge
        #expect(gap >= 8, "the gap between the toggle and the picker is \(gap) points")
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

    /// The right sidebar holds the editor for the selected element, at the
    /// column's own width.
    ///
    /// The bar under the canvas never took the diagram column's width, at any
    /// window size and with the palette either way, because SwiftUI spreads a
    /// scroller across the leading safe area the floating palette states. The
    /// editor now sits in the detail column, which has no such safe area.
    ///
    /// The column draws the default content and the editor in one stack, so
    /// the column holds one scroller while nothing is selected and two while
    /// an editor is in front. The editor is the second.
    @Test func theRightSidebarHoldsTheEditorForTheSelectedElement() async throws {
        let project = await aFlowProject()
        let model = try #require(project.model)
        let component = try #require(model.canvas.components.first)

        for width in [900.0, 1200.0, 1400.0] {
            for palette in [NavigationSplitViewVisibility.all, .detailOnly] {
                project.paletteColumns = palette
                let shown = PaletteColumn.isShowing(palette) ? "shown" : "hidden"
                let canvas = CanvasState()
                canvas.select(componentId: component.id, addingToSelection: false)

                let window = laidOut(
                    ProjectColumns(
                        project: project,
                        session: model,
                        canvas: canvas,
                        stage: .constant(.architecture)
                    ),
                    width: width
                )

                let (sidebar, scrollers) = try sidebarScrollers(in: window)
                #expect(
                    scrollers.count == 2,
                    "the sidebar holds \(scrollers.count) scrollers with a component selected at \(width), palette \(shown)"
                )
                let editorView = try #require(scrollers.last, "no editor at \(width)")
                let editor = editorView.convert(editorView.bounds, to: nil)

                #expect(
                    abs(editor.minX - sidebar.minX) <= 1,
                    "the editor starts at \(editor.minX) and the sidebar at \(sidebar.minX), palette \(shown)"
                )
                #expect(
                    abs(editor.width - sidebar.width) <= 1,
                    "the editor is \(editor.width) wide in a sidebar of \(sidebar.width), palette \(shown)"
                )

                // The window is resized with the editor on screen.
                resize(window, to: width - 200)
                let (resizedSidebar, resizedScrollers) = try sidebarScrollers(in: window)
                let resizedEditorView = try #require(
                    resizedScrollers.last,
                    "no editor after the resize at \(width)"
                )
                let resizedEditor = resizedEditorView.convert(resizedEditorView.bounds, to: nil)
                #expect(
                    abs(resizedEditor.width - resizedSidebar.width) <= 1,
                    "the editor is \(resizedEditor.width) wide in a sidebar of \(resizedSidebar.width) after the resize"
                )

                // Deselecting puts the default content back.
                canvas.clearSelection()
                settle(window)
                let (_, afterScrollers) = try sidebarScrollers(in: window)
                #expect(
                    afterScrollers.count == 1,
                    "the sidebar holds \(afterScrollers.count) scrollers after the selection is cleared at \(width)"
                )
            }
        }
    }

    /// The default content stays in the view tree while an editor is in
    /// front, so its scroll position is the one it had when the person
    /// deselects. A view that is removed and built again starts at the top.
    @Test func theDefaultContentStaysInTheTreeWhileAnEditorIsInFront() async throws {
        let project = await aFlowProject()
        let model = try #require(project.model)
        let component = try #require(model.canvas.components.first)
        let canvas = CanvasState()

        let window = laidOut(
            ProjectColumns(
                project: project,
                session: model,
                canvas: canvas,
                stage: .constant(.architecture)
            ),
            width: 1200
        )
        let (_, empty) = try sidebarScrollers(in: window)
        let defaultContent = try #require(empty.first, "no default content in the sidebar")
        #expect(empty.count == 1, "the sidebar holds \(empty.count) scrollers with nothing selected")

        canvas.select(componentId: component.id, addingToSelection: false)
        settle(window)
        let (_, editing) = try sidebarScrollers(in: window)

        #expect(editing.count == 2, "the sidebar holds \(editing.count) scrollers with an editor in front")
        #expect(
            editing.first === defaultContent,
            "the default content left the view tree, so its scroll position is lost"
        )
    }

    /// Two or more selected elements draw the multi-selection view, and it
    /// offers Merge for two components.
    @Test func theSidebarShowsTheMultiSelectionViewForTwoComponents() async throws {
        let project = await aFlowProject()
        let model = try #require(project.model)
        let canvas = CanvasState()
        canvas.select(componentIds: model.canvas.components.map(\.id))

        let window = laidOut(
            ProjectColumns(
                project: project,
                session: model,
                canvas: canvas,
                stage: .constant(.architecture)
            ),
            width: 1200
        )
        let (sidebar, scrollers) = try sidebarScrollers(in: window)

        #expect(
            scrollers.count == 2,
            "the sidebar holds \(scrollers.count) scrollers with two components selected"
        )
        let viewView = try #require(scrollers.last)
        let view = viewView.convert(viewView.bounds, to: nil)
        #expect(abs(view.width - sidebar.width) <= 1)

        guard case .several(let several) = CanvasSelection.of(session: model, canvas: canvas) else {
            Issue.record("two components show no multi-selection view")
            return
        }
        #expect(several.counts == ["2 components"])
        #expect(several.offersMerge, "the sidebar offers no Merge for two components")
    }

    /// #158: the toggle hides and shows the palette's own column in the real
    /// three-column split, at the leading edge, and not some other column.
    ///
    /// On this macOS, the shown palette draws as a floating panel over the
    /// leading edge of the diagram rather than pushing the diagram column
    /// aside, so the diagram column's frame does not itself move or resize
    /// on the toggle. What does change, and what `NavigationSplitView`
    /// itself uses to hide a column, is whether the split collapses the
    /// palette's own arranged column: collapsed while hidden, not while
    /// shown.
    @Test func togglingThePaletteCollapsesAndExpandsItsOwnColumn() async throws {
        let project = await aDrawnProject()
        let model = try #require(project.model)

        func paletteColumn() throws -> (split: NSSplitView, palette: NSView) {
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
            let palette = try #require(split.arrangedSubviews.first, "the split holds no columns")
            return (split, palette)
        }

        let shown = try paletteColumn()
        #expect(shown.palette.frame.minX == 0, "the palette column sits at \(shown.palette.frame.minX)")
        #expect(
            shown.split.isSubviewCollapsed(shown.palette) == false,
            "the palette starts collapsed"
        )

        project.togglePalette()
        let hidden = try paletteColumn()
        #expect(
            hidden.split.isSubviewCollapsed(hidden.palette),
            "the palette did not collapse after one toggle"
        )

        project.togglePalette()
        let shownAgain = try paletteColumn()
        #expect(
            shownAgain.split.isSubviewCollapsed(shownAgain.palette) == false,
            "the palette did not expand after a second toggle"
        )
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

    /// Every plain button under this one, in window coordinates. The Auto
    /// Sync toggle draws as a plain `NSButton`, never as the `NSPopUpButton`
    /// the pointer picker draws as, so this tells the two apart.
    private func checkboxButtons(in view: NSView, into found: inout [NSRect]) {
        if let button = view as? NSButton, (button is NSPopUpButton) == false {
            found.append(button.convert(button.bounds, to: nil))
        }
        for child in view.subviews { checkboxButtons(in: child, into: &found) }
    }

    /// Every view under this one with nothing under it, in window
    /// coordinates. SwiftUI draws a control's own text beside the control,
    /// so the control's own frame is not always the widest part of it.
    private func leafViews(in view: NSView, into found: inout [NSRect]) {
        if view.subviews.isEmpty {
            found.append(view.convert(view.bounds, to: nil))
        }
        for child in view.subviews { leafViews(in: child, into: &found) }
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

    /// The fifth stage does not widen the panel.
    ///
    /// Five labelled segments are wider than the diagram column, and five
    /// icons are wider than four, so the panel picks the stage with a popup.
    /// A popup is one control wide whatever the number of stages. This
    /// measures the panel the four stages drew and the panel the five stages
    /// draw, at the widest and the narrowest column the split allows, and
    /// states the second is no wider.
    @Test func theFifthStageDoesNotWidenTheWorkflowPanel() async throws {
        let project = await aDrawnProject()
        let model = try #require(project.model)
        let canvas = CanvasState()

        for width in [
            ProjectColumns.minimumDiagramWidth,
            WorkflowPanel.stageWordsWidth,
            WorkflowPanel.allWordsWidth,
            1080.0
        ] {
            let four = NSHostingView(
                rootView: WorkflowPanel(
                    session: project,
                    stage: .constant(.threats),
                    stages: WorkStage.beforeTheReportStage,
                    stageControl: .segments,
                    canvas: canvas,
                    model: model,
                    columnWidth: width
                )
            ).fittingSize.width
            let five = NSHostingView(
                rootView: WorkflowPanel(
                    session: project,
                    stage: .constant(.threats),
                    canvas: canvas,
                    model: model,
                    columnWidth: width
                )
            ).fittingSize.width

            #expect(
                five <= four,
                "in a column of \(width) the five-stage panel needs \(five) and the four-stage panel needed \(four)"
            )
            #expect(
                five <= width,
                "the five-stage panel needs \(five) in a column of \(width)"
            )
        }
    }

    /// The controls that float over the diagram follow the diagram column.
    ///
    /// The person drags the divider of the threats stage. The canvas toolbar
    /// and the workflow panel each have to fit the column at its new width,
    /// so neither of them draws over the threat sidebar.
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
                abs(drawing.width - column.width) <= 1,
                "the canvas is \(drawing.width) wide in a column of \(column.width)"
            )
        }
    }

    /// The workflow panel sits `bottomMargin` above the bottom of the column
    /// it floats over, on every stage, whatever is selected. Nothing is drawn
    /// under the canvas any more, so the panel has nothing to lift over.
    @Test func theWorkflowPanelKeepsTheMarginOnEveryStage() async throws {
        let project = await aFlowProject()
        let model = try #require(project.model)
        let canvas = CanvasState()
        canvas.select(componentId: model.canvas.components[0].id, addingToSelection: false)

        for stage in [WorkStage.architecture, .controls] {
            let window = laidOut(
                ProjectColumns(
                    project: project,
                    session: model,
                    canvas: canvas,
                    stage: .constant(stage)
                )
            )
            let content = try #require(window.contentView)
            var takers: [NSRect] = []
            dropTakers(in: content, into: &takers)
            // The canvas is the tall drop taker and the workflow panel the
            // short one. The Controls stage draws no canvas at all.
            let panel = try #require(
                takers.sorted(by: { $0.height < $1.height }).first,
                "no workflow panel on the \(stage) stage"
            )
            let column = content.convert(content.bounds, to: nil)

            #expect(
                abs((panel.minY - column.minY) - WorkflowPanel.bottomMargin) < 0.5,
                "the panel sits \(panel.minY - column.minY) above the bottom on the \(stage) stage"
            )
        }
    }

    /// The detail column of the architecture split, and every scroller in it
    /// in the order the column stacks them: the default content first, and
    /// the selection editor second while one is in front.
    private func sidebarScrollers(in window: NSWindow) throws -> (NSRect, [NSScrollView]) {
        let content = try #require(window.contentView)
        let split = try #require(columns(in: content))
        let detail = try #require(split.arrangedSubviews.last)
        var found: [NSScrollView] = []
        scrollers(in: detail, into: &found)
        return (detail.convert(detail.bounds, to: nil), found)
    }

    private func scrollers(in view: NSView, into found: inout [NSScrollView]) {
        if let scroll = view as? NSScrollView { found.append(scroll) }
        for child in view.subviews { scrollers(in: child, into: &found) }
    }

    /// Lets AppKit lay the window out again after a change.
    private func settle(_ window: NSWindow) {
        window.contentView?.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.4))
        window.contentView?.layoutSubtreeIfNeeded()
    }

    /// Resizes the window with what it draws already on screen.
    private func resize(_ window: NSWindow, to width: Double) {
        guard let content = window.contentView else { return }
        content.frame = NSRect(x: 0, y: 0, width: width, height: content.frame.height)
        window.setContentSize(content.frame.size)
        settle(window)
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

    /// A project whose model holds one assumption and one mitigates edge.
    private func aSidebarProject() async -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }

              component "guard" { technology = "aws-waf" }

              mitigates guard -> api {
                threats         = ["credential-theft"]
                status          = "proposed"
              }

              assumption "network-segmented" {
                text  = "The network is segmented."
                owner = "platform"
              }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        let session = ProjectSession(useCases: useCases, watcher: FakeProjectWatcher(), defaults: aTestDefaults())
        await session.open(root: "/work")
        return session
    }

    /// The sidebar keeps three sections after the System sheets take the
    /// other seven editors, so its content fits the column the default window
    /// height gives it and a person reads the assumptions with no scroll.
    @Test func theSidebarFitsTheDefaultWindowHeightWithNoScroll() async throws {
        let project = await aSidebarProject()
        let model = try #require(project.model)
        let window = laidOut(ProjectWindow(session: project), width: 1400, height: 900)
        let content = try #require(window.contentView)
        let split = try #require(columns(in: content))
        let column = try #require(split.arrangedSubviews.last).frame

        let host = NSHostingView(rootView: AssumptionsPanel(session: model))
        host.frame = CGRect(x: 0, y: 0, width: column.width, height: 0)
        let drawn = host.fittingSize.height

        #expect(column.height > 0, "the sidebar column measured no height")
        #expect(
            drawn <= column.height,
            "the sidebar draws at \(drawn) in a column of \(column.height)"
        )
    }

    private func laidOut(_ view: some View, width: Double, height: Double) -> NSWindow {
        let hosting = NSHostingView(rootView: view)
        hosting.frame = NSRect(x: 0, y: 0, width: width, height: height)
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

    // MARK: - What answers a click, column by column (#177)

    /// The columns of the stage, back to front.
    ///
    /// `arrangedSubviews` is the order the split lays them out in, and
    /// `subviews` is the order it draws them in. Hit testing follows the
    /// drawing order, so this reads the drawing order.
    private func stageColumns(in content: NSView) -> [NSView] {
        guard let split = columns(in: content) else { return [content] }
        return split.arrangedSubviews.sorted { left, right in
            let order = split.subviews
            return (order.firstIndex(of: left) ?? 0) < (order.firstIndex(of: right) ?? 0)
        }
    }

    /// A grid of points inside a rectangle, clear of its edges.
    private func gridPoints(in frame: NSRect) -> [NSPoint] {
        let margin = 14.0
        let inner = frame.insetBy(dx: margin, dy: margin)
        guard inner.width > 0, inner.height > 0 else { return [] }
        let steps = 4
        return (0..<steps).flatMap { column in
            (0..<steps).map { row in
                NSPoint(
                    x: inner.minX + inner.width * (Double(column) + 0.5) / Double(steps),
                    y: inner.minY + inner.height * (Double(row) + 0.5) / Double(steps)
                )
            }
        }
    }

    /// Every click that lands in a column is answered by a view in that
    /// column, on every stage.
    ///
    /// A layout measurement says where a column is. It does not say what
    /// takes the click that lands on it. #177: every column kept its frame
    /// and the palette took no click, no double click, no drag, no context
    /// menu and no focus. A view drawn over the whole window with hit
    /// testing on answers every point here, so this test fails on it.
    @Test(arguments: WorkStage.allCases)
    func everyColumnAnswersTheClicksThatLandInIt(stage: WorkStage) async throws {
        let project = await aFlowProject()
        let model = try #require(project.model)
        let window = laidOut(
            ProjectColumns(
                project: project,
                session: model,
                canvas: CanvasState(),
                stage: .constant(stage)
            ),
            width: 1400,
            height: 900
        )
        let content = try #require(window.contentView)
        let regions = stageColumns(in: content)
        #expect(regions.isEmpty == false, "the \(stage.label) stage drew no column")

        var answered: Set<ObjectIdentifier> = []
        for (index, region) in regions.enumerated() {
            let over = Array(regions[(index + 1)...])
            for point in gridPoints(in: region.convert(region.bounds, to: nil)) {
                // A column drawn over this one owns the point, and answering
                // it is what that column is for.
                guard over.allSatisfy({ $0.convert($0.bounds, to: nil).contains(point) == false })
                else { continue }

                let answer = content.hitTest(point)
                #expect(
                    answer != nil,
                    "on \(stage.label) nothing answers the click at \(point)"
                )
                guard let answer else { continue }
                answered.insert(ObjectIdentifier(answer))
                #expect(
                    isInside(answer, region),
                    "on \(stage.label) the click at \(point) in column \(index) answered \(viewChain(from: answer))"
                )
            }
        }

        #expect(
            answered.count > 1,
            "on \(stage.label) one view answers every click, which is a view over the columns"
        )
    }

    /// The five places a person clicks on the Architecture stage, and which
    /// column answers each.
    ///
    /// The palette row and the search field are the two #177 reported dead.
    @Test func eachControlOnTheArchitectureStageAnswersItsOwnClicks() async throws {
        let project = await aFlowProject()
        let model = try #require(project.model)
        let window = laidOut(
            ProjectColumns(
                project: project,
                session: model,
                canvas: CanvasState(),
                stage: .constant(.architecture)
            ),
            width: 1400,
            height: 900
        )
        let content = try #require(window.contentView)
        let split = try #require(columns(in: content))
        let palette = try #require(split.arrangedSubviews.first)
        let canvasColumn = split.arrangedSubviews[1]
        let sidebar = try #require(split.arrangedSubviews.last)

        let list = try #require(firstView(of: NSTableView.self, in: palette))
        let row = list.convert(list.rect(ofRow: 1), to: nil)
        let search = try #require(
            views(of: NSTextField.self, in: palette).first { $0 is NSSearchField },
            "the palette drew no search field"
        )
        let panel = try #require(
            views(of: NSPopUpButton.self, in: canvasColumn).min { $0.frame.minY < $1.frame.minY },
            "the canvas column drew no workflow panel control"
        )
        let sidebarField = try #require(
            views(of: NSTextField.self, in: sidebar).first,
            "the right sidebar drew no field"
        )
        let paletteEdge = palette.convert(palette.bounds, to: nil).maxX
        let canvasFrame = canvasColumn.convert(canvasColumn.bounds, to: nil)

        let probes: [(String, NSPoint, NSView)] = [
            ("a palette row", NSPoint(x: row.midX, y: row.midY), palette),
            ("the search field", centre(of: search), palette),
            (
                "the canvas",
                NSPoint(x: (paletteEdge + canvasFrame.maxX) / 2, y: canvasFrame.midY),
                canvasColumn
            ),
            ("the workflow panel", centre(of: panel), canvasColumn),
            ("the right sidebar field", centre(of: sidebarField), sidebar)
        ]

        for (name, point, column) in probes {
            let answer = content.hitTest(point)
            #expect(
                answer.map { isInside($0, column) } == true,
                "\(name) at \(point) answered \(viewChain(from: answer))"
            )
        }
    }

    /// The middle of a view, in window coordinates.
    private func centre(of view: NSView) -> NSPoint {
        let frame = view.convert(view.bounds, to: nil)
        return NSPoint(x: frame.midX, y: frame.midY)
    }

    // MARK: the canvas toolbar's word rule

    @Test func theCanvasToolbarShowsWordsAtAndAboveItsWordsWidth() {
        #expect(CanvasView.toolbarShowsWords(inColumnOfWidth: CanvasView.toolbarWordsWidth))
        #expect(CanvasView.toolbarShowsWords(inColumnOfWidth: CanvasView.toolbarWordsWidth + 200))
    }

    @Test func theCanvasToolbarHidesWordsBelowItsWordsWidthAndAtTheNarrowestDiagramColumn() {
        #expect(CanvasView.toolbarShowsWords(inColumnOfWidth: CanvasView.toolbarWordsWidth - 1) == false)
        #expect(CanvasView.toolbarShowsWords(inColumnOfWidth: ProjectColumns.minimumDiagramWidth) == false)
    }

    @Test func theCanvasToolbarShowsWordsAtAWidthOfNought() {
        #expect(CanvasView.toolbarShowsWords(inColumnOfWidth: 0))
    }

    @Test func theNarrowestDiagramColumnIsBelowTheCanvasToolbarWordsWidth() {
        #expect(ProjectColumns.minimumDiagramWidth < CanvasView.toolbarWordsWidth)
    }

    /// One toolbar-style control, built the same way `canvasToolbar` builds
    /// one: a `Button` with a `Label`, the `ControlWords` modifier, and the
    /// bordered button style.
    private struct AToolbarControl: View {
        let showsWords: Bool
        var body: some View {
            Button {} label: {
                Label("Draw zone", systemImage: "rectangle.dashed")
            }
            .modifier(ControlWords(showsWords: showsWords))
            .buttonStyle(.bordered)
        }
    }

    /// `ControlWords` only ever calls `labelStyle`. macOS keeps a `Label`'s
    /// title as the accessibility label under every `LabelStyle`, so the
    /// words-off control reads the same to a screen reader as the words-on
    /// control reads. This states the two halves that make that true: the
    /// modifier draws a narrower control with the words off, and it sets no
    /// accessibility label of its own for either case, so neither can read
    /// something other than the control's own title.
    @Test func theControlWordsModifierDrawsANarrowerControlWithWordsOffAndSetsNoLabelOfItsOwn() throws {
        let withWords = NSHostingView(rootView: AToolbarControl(showsWords: true)).fittingSize.width
        let withoutWords = NSHostingView(rootView: AToolbarControl(showsWords: false)).fittingSize.width

        #expect(
            withoutWords < withWords,
            "words off measured \(withoutWords), words on measured \(withWords)"
        )

        let source = try String(
            contentsOf: URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("threatmodeller/canvas/CanvasView.swift"),
            encoding: .utf8
        )
        let modifierRange = try #require(
            source.range(of: "struct ControlWords"),
            "CanvasView.swift no longer declares ControlWords"
        )
        let body = source[modifierRange.lowerBound...]

        #expect(
            body.contains(".accessibilityLabel(") == false,
            "ControlWords sets its own accessibility label, so words on and off could read differently"
        )
    }
}
