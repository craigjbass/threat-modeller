import AppKit

/// What the application puts on the pasteboard, and what it reads back.
///
/// A gateway, so a test states what was copied and no test writes to the
/// machine's own pasteboard. `Clipboard.image` carries the two flavours a
/// picture is copied as, so one call writes both.
@MainActor
protocol Clipboard {
    /// Replaces what is on the pasteboard with this text.
    func put(text: String)
    /// What is on the pasteboard as text, or nil.
    func text() -> String?
    /// Replaces what is on the pasteboard with one picture, written as PNG and
    /// as PDF, so the application a person pastes into takes whichever it
    /// reads.
    func put(png: Data, pdf: Data)
}

/// The machine's own pasteboard.
@MainActor
struct SystemClipboard: Clipboard {
    func put(text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    func text() -> String? {
        NSPasteboard.general.string(forType: .string)
    }

    func put(png: Data, pdf: Data) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setData(png, forType: .png)
        NSPasteboard.general.setData(pdf, forType: .pdf)
    }
}
