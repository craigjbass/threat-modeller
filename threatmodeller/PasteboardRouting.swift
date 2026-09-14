import AppKit

/// Which Cut, Copy and Paste a keystroke means.
///
/// One set of menu items carries the standard shortcuts, and what holds the
/// focus decides what they act on: a text field edits its text, and anything
/// else copies the elements the canvas has selected. Two menu items sharing
/// one shortcut would give the user whichever the menu happened to list first.
enum PasteboardRouting {
    enum Target: Equatable {
        /// The field editor: the standard text action, sent to the responder
        /// chain.
        case textField
        /// The elements the canvas has selected.
        case canvas
    }

    static func target(isEditingText: Bool) -> Target {
        isEditingText ? .textField : .canvas
    }

    /// True when a text field, a text view or a field editor holds the focus.
    ///
    /// A `TextField` in SwiftUI on macOS is edited by the window's field
    /// editor, which is an `NSText`, so that one check answers for every text
    /// field in the application.
    @MainActor
    static var isEditingText: Bool {
        guard let responder = NSApp.keyWindow?.firstResponder else { return false }
        if responder is NSText { return true }
        if let view = responder as? NSView, view is NSTextField || view is NSTextView {
            return true
        }
        return false
    }

    /// Sends one standard text action down the responder chain.
    @MainActor
    static func sendToTextField(_ action: Selector) {
        NSApp.sendAction(action, to: nil, from: nil)
    }
}
