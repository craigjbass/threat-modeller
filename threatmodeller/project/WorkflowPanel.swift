import AppKit
import SwiftUI
import ThreatModelKit

/// The stage picker and the two verbs, floating over the diagram.
///
/// The controls act on the diagram, so they sit on it rather than in a band
/// across the window. The panel fits its content: five controls do not need
/// the window's width.
///
/// Auto Sync is not here. It is a setting, not a verb, so it sits in the
/// toolbar beside Libraries.
struct WorkflowPanel: View {
    /// How far the panel floats above the bottom edge of the column.
    static let bottomMargin: CGFloat = 16
    /// The gap the panel keeps above a selection panel.
    static let gapAboveSelectionPanel: CGFloat = 12

    let session: ProjectSession

    /// The stage the window draws. Every stage keeps this panel, so the stage
    /// is a view of the work and never a mode a user has to leave.
    @Binding var stage: WorkStage

    /// The canvas the zoom control acts on, or nil in a stage that draws no
    /// diagram.
    var canvas: CanvasState?
    /// The model the zoom control reads, so Zoom to Fit knows the picture.
    var model: ThreatModelSession?

    /// The tree in front and its canvas, on the Attack Trees stage, or nil
    /// in a stage that draws no tree.
    var trees: TreeEditor?
    var treeCanvas: TreeCanvasState?

    /// How tall the selection panel under the canvas is, or zero when no
    /// selection panel is shown. The panel floats above it.
    var liftedBy: CGFloat = 0

    /// How much room the panel needs under the canvas, so nothing the canvas
    /// draws hides under it. `WindowLayoutTests` measures the panel and states
    /// this number is at least its height.
    static let reservedHeight: CGFloat = 72

    var body: some View {
        row
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .modifier(PanelBackground())
            // A click, a drag or a drop on the panel stops here. Without a
            // shape the gaps between the controls fall through to the canvas.
            .contentShape(.capsule)
            // A technology dropped on the panel is not a technology dropped
            // on the diagram, so the drop stops here and places nothing.
            .dropDestination(for: String.self) { _, _ in false }
            .padding(.bottom, lift)
            .animation(.easeOut(duration: 0.2), value: liftedBy)
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Workflow")
            .accessibilityIdentifier("workflow-bar")
    }

    /// Where the panel draws inside a column, given how big the panel is and
    /// how tall the selection panel under it is.
    ///
    /// The view draws this with `.overlay(alignment: .bottom)` and a bottom
    /// padding. A test reads the same rule, so a change to the padding changes
    /// what the test measures.
    static func rect(in bounds: CGRect, panelSize: CGSize, liftedBy: CGFloat) -> CGRect {
        // With a selection panel under it the panel keeps the gap above that
        // panel. With none it keeps the margin from the bottom edge.
        let bottom = bounds.maxY - lift(over: liftedBy)
        return CGRect(
            x: bounds.midX - panelSize.width / 2,
            y: bottom - panelSize.height,
            width: panelSize.width,
            height: panelSize.height
        )
    }

    /// Where a selection panel of that height draws.
    ///
    /// The column keeps `reservedHeight + bottomMargin` at its bottom edge for
    /// this floating panel, and the selection panel sits on top of that room,
    /// because the column insets the room outside the canvas's own inset.
    static func selectionPanelRect(in bounds: CGRect, height: CGFloat) -> CGRect {
        CGRect(
            x: bounds.minX,
            y: bounds.maxY - reservedRoom - height,
            width: bounds.width,
            height: height
        )
    }

    /// The room the column keeps at its bottom edge for this panel.
    static var reservedRoom: CGFloat { reservedHeight + bottomMargin }

    /// How far above the column's bottom edge the panel draws.
    ///
    /// With no selection panel it keeps the margin. With one it clears the
    /// room kept for itself, then that panel, then the gap: the selection
    /// panel is drawn above the reserved room, so lifting by its height alone
    /// left this panel over its controls.
    static func lift(over selectionPanelHeight: CGFloat) -> CGFloat {
        guard selectionPanelHeight > 0 else { return bottomMargin }
        return reservedRoom + selectionPanelHeight + gapAboveSelectionPanel
    }

    private var lift: CGFloat { Self.lift(over: liftedBy) }

    private var row: some View {
        HStack(spacing: 12) {
            Picker("Stage", selection: $stage) {
                ForEach(WorkStage.allCases) { stage in
                    Label(stage.label, systemImage: stage.systemImage).tag(stage)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .controlSize(.large)
            .fixedSize()
            .accessibilityIdentifier("stage")

            Divider()
                .frame(height: 20)

            Button {
                session.saveNow()
            } label: {
                Label("Synchronise", systemImage: "arrow.triangle.2.circlepath")
            }
            .controlSize(.large)
            .disabled(session.chosenSystem == nil)
            .accessibilityIdentifier("synchronise")

            Button {
                session.compileReport()
            } label: {
                Label("Generate Report", systemImage: "doc.text")
            }
            .controlSize(.large)
            .disabled(session.chosenSystem == nil)
            .accessibilityIdentifier("generate-report")

            if let canvas, let model {
                Divider()
                    .frame(height: 20)

                zoom(
                    CanvasGestures(session: model, canvas: canvas),
                    percentage: canvas.transform.percentage,
                    hasSelection: canvas.hasSelection
                )
            } else if let trees, let treeCanvas {
                Divider()
                    .frame(height: 20)

                zoom(
                    TreeCanvasGestures(editor: trees, canvas: treeCanvas, elements: []),
                    percentage: treeCanvas.transform.percentage,
                    hasSelection: treeCanvas.hasSelection
                )
            }
        }
    }

    /// What the zoom is, and the way to change it. One control for both
    /// canvases, because both zoom through `CanvasZooming`.
    private func zoom(_ gestures: any CanvasZooming, percentage: Int, hasSelection: Bool) -> some View {
        Menu("\(percentage)%") {
            Button("Zoom In") { gestures.zoomAStep(in: true) }
            Button("Zoom Out") { gestures.zoomAStep(in: false) }
            Button("Actual Size") { gestures.zoomToActualSize() }
            Button("Zoom to Fit") { gestures.zoomToFit() }
            Button("Zoom to Selection") { gestures.zoomToSelection() }
                .disabled(hasSelection == false)
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .accessibilityIdentifier("zoom-percentage")
    }
}

/// What the panel is drawn on.
///
/// Glass over a dark zone and glass over a light one both read, because the
/// material takes its contrast from what is behind it. A person who asks for
/// less transparency gets a solid material instead, and every label stays
/// readable.
private struct PanelBackground: ViewModifier {
    func body(content: Content) -> some View {
        if NSWorkspace.shared.accessibilityDisplayShouldReduceTransparency {
            content.background(.regularMaterial, in: .capsule)
                .overlay(Capsule().strokeBorder(.separator))
        } else {
            content.glassEffect(.regular, in: .capsule)
        }
    }
}
