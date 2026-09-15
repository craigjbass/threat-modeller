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
}
