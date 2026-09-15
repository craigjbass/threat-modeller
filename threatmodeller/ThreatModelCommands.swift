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

/// The project in the front window, for the items that act on a project
/// rather than on the drawn model.
struct ProjectSessionKey: FocusedValueKey {
    typealias Value = ProjectSession
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

    var projectSession: ProjectSession? {
        get { self[ProjectSessionKey.self] }
        set { self[ProjectSessionKey.self] = newValue }
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
    @FocusedValue(\.projectSession) private var project

    var body: some Commands {
        CommandGroup(after: .newItem) {
            Button("Open Example\u{2026}") { sampleBrowser?.show() }
                .keyboardShortcut("o", modifiers: [.command, .shift])
                .disabled(sampleBrowser == nil)
                .accessibilityIdentifier("open-example")
        }

        CommandGroup(after: .saveItem) {
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
            // takes back. `Undo` alone when the history is empty.
            Button(session?.undoTitle ?? "Undo") { session?.undo() }
                .keyboardShortcut("z", modifiers: .command)
                .disabled(session?.canUndo != true)

            Button(session?.redoTitle ?? "Redo") { session?.redo() }
                .keyboardShortcut("z", modifiers: [.command, .shift])
                .disabled(session?.canRedo != true)
        }

        // Replacing this group takes the standard Cut, Copy and Paste away
        // from every text field in the application, so these items carry both:
        // what holds the focus decides what they act on. A text field edits its
        // text; anything else acts on what the canvas has selected. Two items
        // sharing one shortcut would give the user whichever the menu listed
        // first, so there is one item per shortcut and it routes.
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
                .disabled(hasSelection == false && canvas?.selectedConnectionIds.isEmpty != false)

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

    private func reorderZones(_ placement: ZonePlacement) {
        guard let session, let canvas else { return }
        CanvasGestures(session: session, canvas: canvas).reorderSelectedZones(placement)
    }

    private var hasSelection: Bool {
        (canvas?.selectedComponentIds.isEmpty == false) || (canvas?.selectedZoneIds.isEmpty == false)
    }

    private func deleteSelection() {
        guard let session, let canvas else { return }
        CanvasGestures(session: session, canvas: canvas).deleteSelection()
    }

    private func withSelection(_ act: (_ componentIds: [String], _ zoneIds: [String]) -> Void) {
        guard let canvas else { return }
        act(Array(canvas.selectedComponentIds), Array(canvas.selectedZoneIds))
    }
}
