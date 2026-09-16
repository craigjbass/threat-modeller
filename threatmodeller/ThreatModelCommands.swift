import AppKit
import SwiftUI
import ThreatModelKit

/// The menu has to act on whichever document is in front. SwiftUI's focused
/// values carry that; a global would be wrong the moment a second window opens.
struct ThreatModelSessionKey: FocusedValueKey {
    typealias Value = ThreatModelSession
}

struct ThreatModelCanvasKey: FocusedValueKey {
    typealias Value = CanvasState
}

/// The menu opens a sheet the document owns, so it carries the action rather
/// than the state.
struct ShowSampleBrowser {
    let show: () -> Void
}

struct ThreatModelSampleBrowserKey: FocusedValueKey {
    typealias Value = ShowSampleBrowser
}

/// The menu shows and hides the palette, which the columns own, so it carries
/// the action rather than the state.
struct TogglePalette {
    let toggle: () -> Void
}

struct ThreatModelPaletteKey: FocusedValueKey {
    typealias Value = TogglePalette
}

/// The project in the front window, for the items that act on a project
/// rather than on the drawn model.
struct ProjectSessionKey: FocusedValueKey {
    typealias Value = ProjectSession
}

/// The tree in front, while the Attack Trees stage is drawn. Undo, Redo,
/// Delete and Select All act on the tree then, and the zoom items on its
/// canvas.
struct TreeEditorKey: FocusedValueKey {
    typealias Value = TreeEditor
}

struct TreeCanvasKey: FocusedValueKey {
    typealias Value = TreeCanvasState
}

extension FocusedValues {
    var threatModelSession: ThreatModelSession? {
        get { self[ThreatModelSessionKey.self] }
        set { self[ThreatModelSessionKey.self] = newValue }
    }

    var threatModelCanvas: CanvasState? {
        get { self[ThreatModelCanvasKey.self] }
        set { self[ThreatModelCanvasKey.self] = newValue }
    }

    var threatModelSampleBrowser: ShowSampleBrowser? {
        get { self[ThreatModelSampleBrowserKey.self] }
        set { self[ThreatModelSampleBrowserKey.self] = newValue }
    }

    var threatModelPalette: TogglePalette? {
        get { self[ThreatModelPaletteKey.self] }
        set { self[ThreatModelPaletteKey.self] = newValue }
    }

    var projectSession: ProjectSession? {
        get { self[ProjectSessionKey.self] }
        set { self[ProjectSessionKey.self] = newValue }
    }

    var treeEditor: TreeEditor? {
        get { self[TreeEditorKey.self] }
        set { self[TreeEditorKey.self] = newValue }
    }

    var treeCanvas: TreeCanvasState? {
        get { self[TreeCanvasKey.self] }
        set { self[TreeCanvasKey.self] = newValue }
    }
}

/// Everything the toolbar and the canvas do, with a menu item and a key.
///
/// Undo and redo **replace** the pair AppKit puts in the Edit menu rather than
/// sitting beside them: two undo stacks that disagree is worse than one.
struct ThreatModelCommands: Commands {
    @FocusedValue(\.threatModelSession) private var session
    @FocusedValue(\.threatModelCanvas) private var canvas
    @FocusedValue(\.threatModelSampleBrowser) private var sampleBrowser
    @FocusedValue(\.threatModelPalette) private var palette
    @FocusedValue(\.projectSession) private var project
    @FocusedValue(\.treeEditor) private var treeEditor
    @FocusedValue(\.treeCanvas) private var treeCanvas

    var body: some Commands {
        CommandGroup(after: .newItem) {
            Button("Open Example\u{2026}") { sampleBrowser?.show() }
                .keyboardShortcut("o", modifiers: [.command, .shift])
                .disabled(sampleBrowser == nil)
                .accessibilityIdentifier("open-example")
        }

        CommandGroup(after: .saveItem) {
            // The one item that reads the disk again outside the
            // files-changed notice. `Divider()` below still separates it from
            // the exports.
            Button("Reload") { reloadProject() }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(project == nil)
                .accessibilityIdentifier("reload-project-menu")

            Divider()

            ForEach(ReportExporter.Kind.allCases, id: \.rawValue) { kind in
                Button(kind.menuTitle) {
                    guard let session else { return }
                    Task { await ReportExporter(session: session).export(kind) }
                }
                .disabled(session == nil)
                .accessibilityIdentifier("export-\(kind.rawValue)")
            }

            Divider()

            // A report this application wrote, opened where a person reads
            // Markdown. A report written by `threatmodeller compile` outside
            // this application is not known here, so the item stays off.
            Button("Open Last Report") { project?.openLastReport() }
                .disabled(project?.canOpenReport != true)
                .accessibilityIdentifier("open-last-report")
        }

        CommandGroup(replacing: .undoRedo) {
            // The menu names the change, so a person knows what pressing it
            // takes back. `Undo` alone when the history is empty. A tree is
            // not in the model, so the tree in front keeps its own history.
            Button(undoTitle) {
                if let treeEditor { treeEditor.undo() } else { session?.undo() }
            }
            .keyboardShortcut("z", modifiers: .command)
            .disabled(canUndo == false)

            Button(redoTitle) {
                if let treeEditor { treeEditor.redo() } else { session?.redo() }
            }
            .keyboardShortcut("z", modifiers: [.command, .shift])
            .disabled(canRedo == false)
        }

        // Replacing this group takes the standard Cut, Copy and Paste away
        // from every text field in the application, so these items carry both:
        // what holds the focus decides what they act on. A text field edits its
        // text; anything else acts on what the canvas has selected. Two items
        // sharing one shortcut would give the user whichever the menu listed
        // first, so there is one item per shortcut and it routes.
        // The View menu. Laying the diagram out again is how a person gets a
        // picture back after an hour of dragging one by hand.
        CommandMenu("View") {
            // The standard sidebar button writes to the split view's own
            // visibility. This item writes the same state, so a person has a
            // menu item and a key for it as well as the button.
            Button("Show or Hide Palette") { palette?.toggle() }
                .keyboardShortcut("s", modifiers: [.command, .control])
                .disabled(palette == nil)
                .accessibilityIdentifier("toggle-palette")

            Button("Lay Out Diagram") {
                guard let project else { return }
                Task { await project.layOutDiagram() }
            }
            .keyboardShortcut("l", modifiers: [.command, .shift])
            .disabled(project?.model == nil)
            .accessibilityIdentifier("lay-out-diagram")

            Button("Zoom In") { zoom { $0.zoomAStep(in: true) } }
                .keyboardShortcut("=", modifiers: .command)
                .disabled(canvas == nil)
                .accessibilityIdentifier("zoom-in-command")

            Button("Zoom Out") { zoom { $0.zoomAStep(in: false) } }
                .keyboardShortcut("-", modifiers: .command)
                .disabled(canvas == nil)
                .accessibilityIdentifier("zoom-out-command")

            Button("Actual Size") { zoom { $0.zoomToActualSize() } }
                .keyboardShortcut("0", modifiers: .command)
                .disabled(canvas == nil)
                .accessibilityIdentifier("actual-size")

            Button("Zoom to Fit") { zoom { $0.zoomToFit() } }
                .keyboardShortcut("9", modifiers: .command)
                .disabled(canvas == nil)
                .accessibilityIdentifier("zoom-to-fit")

            Button("Zoom to Selection") { zoom { $0.zoomToSelection() } }
                .disabled(hasSelection == false)
                .accessibilityIdentifier("zoom-to-selection")

            Divider()

            // One key per stage, in the stage order.
            Button("Architecture") { canvas?.showStage?(.architecture) }
                .keyboardShortcut("1", modifiers: .command)
                .disabled(canvas?.showStage == nil)
                .accessibilityIdentifier("stage-architecture")

            Button("Attack Trees") { canvas?.showStage?(.attackTrees) }
                .keyboardShortcut("2", modifiers: .command)
                .disabled(canvas?.showStage == nil)
                .accessibilityIdentifier("stage-attack-trees")

            Button("Threats") { canvas?.showStage?(.threats) }
                .keyboardShortcut("3", modifiers: .command)
                .disabled(canvas?.showStage == nil)
                .accessibilityIdentifier("stage-threats")

            Button("Controls") { canvas?.showStage?(.controls) }
                .keyboardShortcut("4", modifiers: .command)
                .disabled(canvas?.showStage == nil)
                .accessibilityIdentifier("stage-controls")

            Divider()

            Button("Lay Out Selection") {
                guard let project, let canvas else { return }
                Task {
                    await project.layOutDiagram(
                        componentIds: Array(canvas.selectedComponentIds),
                        zoneIds: Array(canvas.selectedZoneIds)
                    )
                }
            }
            .keyboardShortcut("l", modifiers: [.command, .option])
            .disabled(hasSelection == false)
            .accessibilityIdentifier("lay-out-selection")
        }

        CommandGroup(replacing: .pasteboard) {
            Button("Cut") {
                switch PasteboardRouting.target(isEditingText: PasteboardRouting.isEditingText) {
                case .textField:
                    PasteboardRouting.sendToTextField(#selector(NSText.cut(_:)))
                case .canvas:
                    withSelection { session?.cutSelection(componentIds: $0, zoneIds: $1) }
                }
            }
            .keyboardShortcut("x", modifiers: .command)

            Button("Copy") {
                switch PasteboardRouting.target(isEditingText: PasteboardRouting.isEditingText) {
                case .textField:
                    PasteboardRouting.sendToTextField(#selector(NSText.copy(_:)))
                case .canvas:
                    withSelection { session?.copySelection(componentIds: $0, zoneIds: $1) }
                }
            }
            .keyboardShortcut("c", modifiers: .command)

            Button("Paste") {
                switch PasteboardRouting.target(isEditingText: PasteboardRouting.isEditingText) {
                case .textField:
                    PasteboardRouting.sendToTextField(#selector(NSText.paste(_:)))
                case .canvas:
                    guard let session, let canvas else { return }
                    let pasted = session.paste()
                    canvas.selectAll(componentIds: pasted.componentIds, zoneIds: pasted.zoneIds)
                }
            }
            .keyboardShortcut("v", modifiers: .command)

            Button("Select All") {
                switch PasteboardRouting.target(isEditingText: PasteboardRouting.isEditingText) {
                case .textField:
                    PasteboardRouting.sendToTextField(#selector(NSText.selectAll(_:)))
                case .canvas:
                    if let treeEditor, let treeCanvas {
                        TreeCanvasGestures(editor: treeEditor, canvas: treeCanvas, elements: []).selectAll()
                        return
                    }
                    guard let session, let canvas else { return }
                    canvas.selectAll(componentIds: session.canvas.components.map(\.id), zoneIds: [])
                }
            }
            .keyboardShortcut("a", modifiers: .command)

            // The picture, where a person can paste it, rather than a file
            // they have to find and drag.
            Button("Copy as Image") {
                guard let session, let canvas else { return }
                session.copyDiagramAsImage(
                    componentIds: Array(canvas.selectedComponentIds),
                    zoneIds: Array(canvas.selectedZoneIds)
                )
            }
            .keyboardShortcut("c", modifiers: [.command, .shift])
            .disabled(session == nil)
            .accessibilityIdentifier("copy-as-image")

            Button("Duplicate") {
                guard let session, let canvas else { return }
                withSelection { componentIds, zoneIds in
                    let made = session.duplicate(componentIds: componentIds, zoneIds: zoneIds)
                    canvas.selectAll(componentIds: made.componentIds, zoneIds: made.zoneIds)
                }
            }
            .keyboardShortcut("d", modifiers: .command)
            .disabled(hasSelection == false)

            Divider()

            // The canvas answers the Delete key, but only while it has focus,
            // and replacing the pasteboard group took the standard item away.
            // A command a user cannot find is a command they do not have.
            Button("Delete") { deleteSelection() }
                .keyboardShortcut(.delete, modifiers: [])
                .disabled(
                    hasSelection == false
                        && canvas?.selectedConnectionIds.isEmpty != false
                        && treeCanvas?.hasSelection != true
                )

            Divider()

            // The threat list holds its order while a person answers it. This
            // is how a person puts it back to worst first without reaching
            // for the sidebar.
            Button("Reorder Threats") { session?.resortThreats() }
                .keyboardShortcut("r", modifiers: [.command, .shift])
                .disabled(session?.rowsOutOfOrder ?? 0 == 0)

            Divider()

            // Two zones that overlap need an order a person can state,
            // because the zone drawn last takes the click.
            Button("Bring Zone to Front") { reorderZones(.front) }
                .keyboardShortcut("]", modifiers: [.command, .option])
                .disabled(canvas?.selectedZoneIds.isEmpty != false)
                .accessibilityIdentifier("bring-zone-to-front")

            Button("Send Zone to Back") { reorderZones(.back) }
                .keyboardShortcut("[", modifiers: [.command, .option])
                .disabled(canvas?.selectedZoneIds.isEmpty != false)
                .accessibilityIdentifier("send-zone-to-back")
        }
    }

    /// Runs one zoom command on the canvas in front: the tree canvas while
    /// the Attack Trees stage is drawn, and the diagram otherwise.
    private func zoom(_ act: (any CanvasZooming) -> Void) {
        if let treeEditor, let treeCanvas {
            return act(TreeCanvasGestures(editor: treeEditor, canvas: treeCanvas, elements: []))
        }
        guard let session, let canvas else { return }
        act(CanvasGestures(session: session, canvas: canvas))
    }

    private var undoTitle: String {
        if let treeEditor { return treeEditor.undoLabel.map { "Undo \($0)" } ?? "Undo" }
        return session?.undoTitle ?? "Undo"
    }

    private var redoTitle: String {
        if let treeEditor { return treeEditor.redoLabel.map { "Redo \($0)" } ?? "Redo" }
        return session?.redoTitle ?? "Redo"
    }

    private var canUndo: Bool {
        if let treeEditor { return treeEditor.canUndo }
        return session?.canUndo == true
    }

    private var canRedo: Bool {
        if let treeEditor { return treeEditor.canRedo }
        return session?.canRedo == true
    }

    private func reorderZones(_ placement: ZonePlacement) {
        guard let session, let canvas else { return }
        CanvasGestures(session: session, canvas: canvas).reorderSelectedZones(placement)
    }

    private var hasSelection: Bool {
        if let treeCanvas { return treeCanvas.hasSelection }
        return (canvas?.selectedComponentIds.isEmpty == false) || (canvas?.selectedZoneIds.isEmpty == false)
    }

    private func deleteSelection() {
        if let treeEditor, let treeCanvas {
            return TreeCanvasGestures(editor: treeEditor, canvas: treeCanvas, elements: []).deleteSelection()
        }
        guard let session, let canvas else { return }
        CanvasGestures(session: session, canvas: canvas).deleteSelection()
    }

    private func withSelection(_ act: (_ componentIds: [String], _ zoneIds: [String]) -> Void) {
        guard let canvas else { return }
        act(Array(canvas.selectedComponentIds), Array(canvas.selectedZoneIds))
    }

    /// Reads the project's files again, and keeps the selection where the
    /// reloaded model still holds the element.
    private func reloadProject() {
        guard let project, let canvas else { return }
        project.reload(keepingSelectionIn: canvas)
    }
}
