import SwiftUI

/// A name edited in place, on the element itself.
///
/// It differs from `DeferredTextField` in two ways. It takes the focus as it
/// appears. The end of the edit always calls `write`, because `write` closes
/// the field, while a panel field stays open and writes only what the edit
/// changed.
struct InlineNameField: View {
    let text: String
    let width: CGFloat
    let identifier: String
    let write: (String) -> Void
    let cancel: () -> Void

    @State private var edit: DeferredEdit<String>
    @FocusState private var isFocused: Bool

    init(
        text: String,
        width: CGFloat,
        identifier: String,
        edit: DeferredEdit<String> = DeferredEdit(),
        write: @escaping (String) -> Void,
        cancel: @escaping () -> Void
    ) {
        self.text = text
        self.width = width
        self.identifier = identifier
        self.write = write
        self.cancel = cancel
        _edit = State(initialValue: edit)
    }

    var body: some View {
        TextField(
            "Name",
            text: Binding(
                get: { edit.shown(text) },
                set: { edit.edit($0) }
            )
        )
        .textFieldStyle(.roundedBorder)
        .font(.headline)
        .frame(width: width)
        .focused($isFocused)
        .accessibilityIdentifier(identifier)
        .onAppear { isFocused = true }
        .onSubmit { endTheEdit() }
        .onExitCommand { cancelTheEdit() }
        .onChange(of: isFocused) { _, focused in
            if focused == false { endTheEdit() }
        }
    }

    /// Ends the edit and writes the name the field shows.
    func endTheEdit() {
        write(edit.end(from: text) ?? text)
    }

    /// Drops the edit, writes nothing, and closes the field.
    func cancelTheEdit() {
        edit.cancel()
        cancel()
    }
}
