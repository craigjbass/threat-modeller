import SwiftUI
import ThreatModelKit

/// The columns of one stage.
///
/// Each stage drops the columns it does not need. The palette is only of use
/// while the architecture is being drawn, and the diagram says nothing about
/// which control a team runs, so the answers take the whole window. The Report
/// stage draws the sections, the reading column and the report's controls.
struct ProjectColumns: View {
    let project: ProjectSession
    let session: ThreatModelSession
    let canvas: CanvasState

    /// The stage the window draws. The floating panel changes it, so the
    /// columns hold a binding rather than a value.
    @Binding var stage: WorkStage

    /// The tree in front and its canvas. The window owns both, so the tree
    /// survives a change of stage; a caller with no window takes fresh ones.
    var trees = TreeEditor()
    var treeCanvas = TreeCanvasState()

    /// The narrowest each side of the threats stage goes.
    static let minimumDiagramWidth: CGFloat = 400
    static let minimumThreatListWidth: CGFloat = 320

    @State private var isSampleBrowserOpen = false

    /// Which columns the architecture stage shows. The window holds it, so
    /// the sidebar button, the menu item and the key all write one state.
    private var columns: Binding<NavigationSplitViewVisibility> {
        Binding(
            get: { project.paletteColumns },
            set: { project.paletteColumns = $0 }
        )
    }

    var body: some View {
        stageColumns
            .focusedSceneValue(\.threatModelPalette, TogglePalette {
                project.togglePalette()
            })
            .focusedSceneValue(\.threatModelSampleBrowser, ShowSampleBrowser {
                isSampleBrowserOpen = true
            })
            .sheet(isPresented: $isSampleBrowserOpen) {
                SampleBrowser(session: session, canvas: canvas)
            }
    }

    @ViewBuilder
    private var stageColumns: some View {
        switch stage {
        case .architecture:
            NavigationSplitView(columnVisibility: columns) {
                PaletteView(session: session, canvas: canvas, project: project)
                    .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            } content: {
                diagram
            } detail: {
                // The column holds the editor for what is selected, and the
                // assumptions when nothing is. The design states the rule.
                SelectionSidebar(session: session, canvas: canvas)
                    // The cap keeps the spare width with the canvas: without
                    // it, closing the palette widens this column and squeezes
                    // the canvas to its minimum.
                    .navigationSplitViewColumnWidth(min: 280, ideal: 360, max: 480)
            }
        case .attackTrees:
            NavigationSplitView(columnVisibility: columns) {
                TreeSidebar(
                    project: project,
                    session: session,
                    editor: trees,
                    canvas: treeCanvas,
                    elements: treeElements,
                    bound: session.attackTrees
                )
                .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            } content: {
                treeDiagram
            } detail: {
                TreeSelectionPanel(
                    editor: trees,
                    canvas: treeCanvas,
                    bound: boundTree,
                    elements: treeElements,
                    controls: modelControls
                )
                .navigationSplitViewColumnWidth(min: 280, ideal: 360, max: 480)
            }
        case .threats:
            // A plain split, not a `NavigationSplitView`. A sidebar column
            // takes the sidebar material behind whatever it holds and the
            // standard toggle collapses it, and a canvas is neither of those
            // things. `HSplitView` gives a divider the person drags, and the
            // width holds while the window is open.
            HSplitView {
                diagram
                    .frame(minWidth: Self.minimumDiagramWidth)
                ThreatSidebar(session: session, focus: .likelihood)
                    .frame(minWidth: Self.minimumThreatListWidth, idealWidth: 420)
            }
        case .controls:
            ThreatSidebar(session: session, focus: .controls, project: project)
                .overlay(alignment: .bottom) {
                    floating { workflowPanel(inColumnOfWidth: $0) }
                }
        case .report:
            ReportStage(project: project, session: session, stage: $stage)
        }
    }

    /// The canvas, with room kept under it for the floating panel and the
    /// panel drawn over that room, so nothing the canvas draws hides under it.
    private var diagram: some View {
        CanvasView(session: session, canvas: canvas, pointerMode: project.pointerMode)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                Color.clear.frame(
                    height: WorkflowPanel.reservedHeight + WorkflowPanel.bottomMargin
                )
            }
            .overlay(alignment: .bottom) {
                floating { workflowPanel(inColumnOfWidth: $0) }
            }
            .navigationTitle("Diagram")
            // One width, stated once, for the one column that holds the
            // diagram. The threats stage states its own minimum on the split.
            .navigationSplitViewColumnWidth(min: Self.minimumDiagramWidth, ideal: 700)
    }

    /// The tree canvas, with the same room kept under it for the floating
    /// panel that the diagram keeps.
    private var treeDiagram: some View {
        TreeCanvas(
            editor: trees,
            canvas: treeCanvas,
            elements: treeElements,
            bound: boundTree,
            pointerMode: project.pointerMode
        )
            .safeAreaInset(edge: .bottom, spacing: 0) {
                Color.clear.frame(
                    height: WorkflowPanel.reservedHeight + WorkflowPanel.bottomMargin
                )
            }
            .overlay(alignment: .bottom) {
                floating { width in
                    WorkflowPanel(
                        session: project,
                        stage: $stage,
                        trees: trees,
                        treeCanvas: treeCanvas,
                        columnWidth: width
                    )
                }
            }
            .navigationTitle("Attack Trees")
            .navigationSplitViewColumnWidth(min: Self.minimumDiagramWidth, ideal: 700)
    }

    /// The elements the `.arch` file states, with the threats raised on each.
    private var treeElements: [TreeElement] {
        TreeElement.list(
            threats: session.threats,
            components: session.canvas.components,
            connections: session.canvas.connections,
            zones: session.canvas.zones
        )
    }

    /// Every control description the model holds, once each, in
    /// alphabetical order, for the sufficient control menu.
    private var modelControls: [String] {
        Array(Set(session.threats.flatMap(\.controls).map(\.description))).sorted()
    }

    /// What the assessment bound for the tree in front, or nil.
    private var boundTree: BoundAttackTree? {
        session.attackTrees.first { $0.id == trees.id }
    }

    /// The five controls, floating at the bottom middle of the column they
    /// act on, `WorkflowPanel.bottomMargin` above its bottom edge.
    private func workflowPanel(inColumnOfWidth width: CGFloat) -> some View {
        WorkflowPanel(
            session: project,
            stage: $stage,
            canvas: canvas,
            model: session,
            columnWidth: width
        )
    }

    /// Draws a floating panel at the bottom of the column it floats over, and
    /// tells the panel how wide that column is.
    ///
    /// The reader takes the column's own width. A canvas is as wide as the
    /// drawing inside it, which is thousands of points, so a panel that
    /// measures itself against the canvas never sees the column narrow.
    private func floating(
        @ViewBuilder _ panel: @escaping (CGFloat) -> some View
    ) -> some View {
        GeometryReader { geometry in
            panel(geometry.size.width)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottom)
        }
    }
}


/// Which columns the palette sits in, and what the toggle does to them.
///
/// `NavigationSplitViewVisibility` states more than two states, and a person
/// pressing a toggle means one thing: show the palette, or hide it. The
/// Architecture stage draws a three-column split, and that split does not
/// honour `.detailOnly`: setting it left every column's measured width
/// where it was (see #143). `.doubleColumn` is the state the split does
/// honour to drop the leading, palette column, so the toggle maps to
/// `.doubleColumn` and `.all`, never to `.detailOnly`.
nonisolated enum PaletteColumn {
    static func toggled(_ visibility: NavigationSplitViewVisibility) -> NavigationSplitViewVisibility {
        visibility == .doubleColumn ? .all : .doubleColumn
    }

    /// True while the palette is on screen.
    static func isShowing(_ visibility: NavigationSplitViewVisibility) -> Bool {
        visibility != .doubleColumn
    }
}
