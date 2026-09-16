import SwiftUI

/// A field in a panel that writes one change when the edit ends.
///
/// A field bound straight to a use case writes once per keystroke, which costs
/// one rescore per letter and fills the undo history with letters. This field
/// holds the edit in a `DeferredEdit`, writes on Return and on losing the
/// focus, and follows the model while nobody is typing in it.
struct DeferredTextField: View {
    let title: String
    let text: String
    /// Nil leaves the field as wide as the column it sits in. A panel that
    /// lays its controls out in a row states a width.
    var width: CGFloat? = nil
    let identifier: String
    /// How many lines the field grows to. Nil keeps it on one line.
    var lines: ClosedRange<Int>? = nil
    let commit: (String) -> Void

    @State private var edit = DeferredEdit<String>()
    @FocusState private var isFocused: Bool

    var body: some View {
        TextField(
            title,
            text: Binding(
                get: { edit.shown(text) },
                set: { edit.edit($0) }
            ),
            axis: lines == nil ? .horizontal : .vertical
        )
        .lineLimit(lines ?? 1 ... 1)
        .textFieldStyle(.roundedBorder)
        .frame(width: width)
        .focused($isFocused)
        .accessibilityIdentifier(identifier)
        .onSubmit { write() }
        .onChange(of: isFocused) { _, focused in
            // Clicking elsewhere takes the focus away, and that writes: a
            // person who typed a name and looked away means the name.
            if focused == false { write() }
        }
    }

    private func write() {
        guard let typed = edit.end(from: text) else { return }
        commit(typed)
    }
}
