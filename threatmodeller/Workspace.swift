import AppKit

/// What opens a file in another application, and what shows it in Finder.
///
/// A protocol so a test states what was opened and no test opens anything.
@MainActor
protocol Workspace {
    /// Opens the file in the application the person uses for that kind of
    /// file. It answers false when no application opens it.
    @discardableResult
    func open(path: String) -> Bool
    /// Shows the file in Finder, selected in its folder.
    func reveal(path: String)
}

/// The real one.
@MainActor
struct SystemWorkspace: Workspace {
    @discardableResult
    func open(path: String) -> Bool {
        NSWorkspace.shared.open(URL(fileURLWithPath: path))
    }

    func reveal(path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }
}
