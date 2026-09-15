import SwiftUI
import ThreatModelKit

/// The columns of one stage.
///
/// Each stage drops the columns it does not need. The palette is only of use
/// while the architecture is being drawn, and the diagram says nothing about
/// which control a team runs, so the answers take the whole window.
struct ProjectColumns: View {
    let project: ProjectSession
    let session: ThreatModelSession
    let canvas: CanvasState

    /// The stage the window draws. The floating panel changes it, so the
    /// columns hold a binding rather than a value.
    @Binding var stage: WorkStage

    @State private var isSampleBrowserOpen = false

    var body: some View {
        columns
            .focusedSceneValue(\.threatModelSampleBrowser, ShowSampleBrowser {
                isSampleBrowserOpen = true
            })
            .sheet(isPresented: $isSampleBrowserOpen) {
                SampleBrowser(session: session, canvas: canvas)
            }
    }

    @ViewBuilder
    private var columns: some View {
        switch stage {
        case .architecture:
            NavigationSplitView {
                PaletteView(session: session, canvas: canvas)
                    .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            } content: {
                diagram
            } detail: {
                AssumptionsPanel(session: session)
                    .navigationSplitViewColumnWidth(min: 280, ideal: 360)
            }
        case .threats:
            NavigationSplitView {
                diagram
                    .navigationSplitViewColumnWidth(min: 400, ideal: 640)
            } detail: {
                ThreatSidebar(session: session, focus: .likelihood)
                    .navigationSplitViewColumnWidth(min: 320, ideal: 420)
            }
        case .controls:
            ThreatSidebar(session: session, focus: .controls, project: project)
                .overlay(alignment: .bottom) { workflowPanel }
        }
    }

    /// The canvas, with room kept under it for the floating panel and the
    /// panel drawn over that room, so nothing the canvas draws hides under it.
    private var diagram: some View {
        CanvasView(session: session, canvas: canvas)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                Color.clear.frame(
                    height: WorkflowPanel.reservedHeight + WorkflowPanel.bottomMargin
                )
            }
            .overlay(alignment: .bottom) { workflowPanel }
            .navigationTitle("Diagram")
            .navigationSplitViewColumnWidth(min: 400, ideal: 700)
    }

    /// The five controls, floating at the bottom middle of the column they
    /// act on.
    private var workflowPanel: some View {
        WorkflowPanel(
            session: project,
            stage: $stage,
            liftedBy: canvas.selectionPanelHeight
        )
    }
}
