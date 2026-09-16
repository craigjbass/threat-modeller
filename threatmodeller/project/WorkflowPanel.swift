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

    let session: ProjectSession

    /// The stage the window draws. Every stage keeps this panel, so the stage
    /// is a view of the work and never a mode a user has to leave.
    @Binding var stage: WorkStage

    /// The stages the picker offers. Every stage, unless a caller states
    /// fewer.
    var stages: [WorkStage] = WorkStage.allCases

    /// Which control picks the stage.
    ///
    /// The popup is what the panel draws. `.segments` is the control the
    /// four-stage panel drew before the Report stage, kept so
    /// `WindowLayoutTests` measures the panel the five-stage panel must not
    /// grow past.
    enum StageControl {
        case popup
        case segments
    }

    var stageControl: StageControl = .popup

    /// The canvas the zoom control acts on, or nil in a stage that draws no
    /// diagram.
    var canvas: CanvasState?
    /// The model the zoom control reads, so Zoom to Fit knows the picture.
    var model: ThreatModelSession?

    /// The tree in front and its canvas, on the Attack Trees stage, or nil
    /// in a stage that draws no tree.
    var trees: TreeEditor?
    var treeCanvas: TreeCanvasState?

    /// How wide the column the panel floats over is, or zero when the caller
    /// has not measured it. The panel drops the words it cannot fit, so it
    /// needs the column's current width and not the width of the view it
    /// floats over, which is as wide as the drawing inside it.
    var columnWidth: CGFloat = 0

    /// The width the panel needs with every word shown.
    static let allWordsWidth: CGFloat = 860

    /// The width the panel needs with the stage words and the verbs as icons.
    static let stageWordsWidth: CGFloat = 660

    /// True while the column is wide enough for the stage words.
    ///
    /// A column of nought is a column nobody measured. The words are what the
    /// person reads first, so an unmeasured column shows them.
    static func showsStageWords(inColumnOfWidth width: CGFloat) -> Bool {
        width <= 0 || width >= stageWordsWidth
    }

    /// True while the column is wide enough for the words on the two verbs.
    static func showsVerbWords(inColumnOfWidth width: CGFloat) -> Bool {
        width <= 0 || width >= allWordsWidth
    }

    /// How much room the panel needs under the canvas, so nothing the canvas
    /// draws hides under it. `WindowLayoutTests` measures the panel and states
    /// this number is at least its height.
    static let reservedHeight: CGFloat = 72

    /// The column the panel floats over is as narrow as
    /// `ProjectColumns.minimumDiagramWidth`, and the person changes that width
    /// with the divider of the threats stage. The row with every word shown
    /// needs more room than the narrowest column has, so a column that cannot
    /// hold the words gets the icons alone. Without that the panel ran past
    /// both edges of the column and drew over the threat sidebar.
    var body: some View {
        panel(
            stageWords: Self.showsStageWords(inColumnOfWidth: columnWidth),
            verbWords: Self.showsVerbWords(inColumnOfWidth: columnWidth)
        )
        .padding(.bottom, Self.bottomMargin)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Workflow")
        .accessibilityIdentifier("workflow-bar")
    }

    private func panel(stageWords: Bool, verbWords: Bool) -> some View {
        row(stageWords: stageWords, verbWords: verbWords)
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .modifier(PanelBackground())
            // A click, a drag or a drop on the panel stops here. Without a
            // shape the gaps between the controls fall through to the canvas.
            .contentShape(.capsule)
            // A technology dropped on the panel is not a technology dropped
            // on the diagram, so the drop stops here and places nothing.
            .dropDestination(for: String.self) { _, _ in false }
    }

    /// The controls of the panel.
    ///
    /// The words go in two steps as the column narrows: the two verbs lose
    /// theirs first, and the stage picker keeps its own for as long as the
    /// column holds them, because the stage is what the person reads first.
    private func row(stageWords: Bool, verbWords: Bool) -> some View {
        HStack(spacing: 12) {
            stagePicker(showsWords: stageWords)

            Divider()
                .frame(height: 20)

            Button {
                session.saveNow()
            } label: {
                Label("Synchronise", systemImage: "arrow.triangle.2.circlepath")
            }
            .controlSize(.large)
            .disabled(session.chosenSystem == nil)
            .modifier(ControlWords(showsWords: verbWords))
            .accessibilityIdentifier("synchronise")

            Button {
                session.compileReport()
            } label: {
                Label("Generate Report", systemImage: "doc.text")
            }
            .controlSize(.large)
            .disabled(session.chosenSystem == nil)
            .modifier(ControlWords(showsWords: verbWords))
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

    /// The control that picks the stage.
    ///
    /// A popup is one control wide whatever the number of stages: it names the
    /// stage the window draws and lists the rest. Five labelled segments are
    /// wider than the diagram column, and five icons are wider than four, so
    /// the popup is what keeps the panel inside the column the fifth stage
    /// arrived in. A narrow column takes the icon alone, the way the two verbs
    /// do.
    @ViewBuilder
    private func stagePicker(showsWords: Bool) -> some View {
        switch stageControl {
        case .popup:
            Picker("Stage", selection: $stage) {
                ForEach(stages) { choice in
                    Label(choice.label, systemImage: choice.systemImage).tag(choice)
                }
            }
            .pickerStyle(.menu)
            .labelsHidden()
            .controlSize(.large)
            .fixedSize()
            .modifier(ControlWords(showsWords: showsWords))
            .accessibilityIdentifier("stage")
        case .segments:
            Picker("Stage", selection: $stage) {
                ForEach(stages) { choice in
                    Label(choice.label, systemImage: choice.systemImage).tag(choice)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .controlSize(.large)
            .fixedSize()
            .modifier(ControlWords(showsWords: showsWords))
            .accessibilityIdentifier("stage")
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
