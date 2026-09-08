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

extension FocusedValues {
    var threatModelSession: ThreatModelSession? {
        get { self[ThreatModelSessionKey.self] }
        set { self[ThreatModelSessionKey.self] = newValue }
    }

    var threatModelCanvas: CanvasState? {
        get { self[ThreatModelCanvasKey.self] }
        set { self[ThreatModelCanvasKey.self] = newValue }
    }
}

/// Everything the toolbar and the canvas do, with a menu item and a key.
///
/// Undo and redo **replace** the document's own pair rather than sitting beside
/// them: `DocumentGroup` installs `NSUndoManager`'s, and two undo stacks that
/// disagree is worse than one.
struct ThreatModelCommands: Commands {
    @FocusedValue(\.threatModelSession) private var session
    @FocusedValue(\.threatModelCanvas) private var canvas

    var body: some Commands {
        CommandGroup(replacing: .undoRedo) {
            Button("Undo") { session?.undo() }
                .keyboardShortcut("z", modifiers: .command)
                .disabled(session?.canUndo != true)

            Button("Redo") { session?.redo() }
                .keyboardShortcut("z", modifiers: [.command, .shift])
                .disabled(session?.canRedo != true)
        }

        CommandGroup(replacing: .pasteboard) {
            Button("Cut") { withSelection { session?.cutSelection(componentIds: $0, zoneIds: $1) } }
                .keyboardShortcut("x", modifiers: .command)
                .disabled(hasSelection == false)

            Button("Copy") { withSelection { session?.copySelection(componentIds: $0, zoneIds: $1) } }
                .keyboardShortcut("c", modifiers: .command)
                .disabled(hasSelection == false)

            Button("Paste") {
                guard let session, let canvas else { return }
                let pasted = session.paste()
                canvas.selectAll(componentIds: pasted.componentIds, zoneIds: pasted.zoneIds)
            }
            .keyboardShortcut("v", modifiers: .command)

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

            Button("Select All") {
                guard let session, let canvas else { return }
                canvas.selectAll(componentIds: session.canvas.components.map(\.id), zoneIds: [])
            }
            .keyboardShortcut("a", modifiers: .command)
        }
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
