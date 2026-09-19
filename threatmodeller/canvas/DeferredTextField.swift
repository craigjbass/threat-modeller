import SwiftUI

/// A field in a panel that holds its edit in a `DeferredEdit` and follows the
/// model while nobody is typing in it.
struct DeferredTextField: View {
    let title: String
    let text: String
    /// Nil leaves the field as wide as the column it sits in. A panel that
    /// lays its controls out in a row states a width.
    let width: CGFloat?
    let identifier: String
    /// How many lines the field grows to. Nil keeps it on one line.
    let lines: ClosedRange<Int>?
    let write: (String) -> Void

    @State private var edit: DeferredEdit<String>
    @FocusState private var isFocused: Bool

    init(
        title: String,
        text: String,
        width: CGFloat? = nil,
        identifier: String,
        lines: ClosedRange<Int>? = nil,
        edit: DeferredEdit<String> = DeferredEdit(),
        write: @escaping (String) -> Void
    ) {
        self.title = title
        self.text = text
        self.width = width
        self.identifier = identifier
        self.lines = lines
        self.write = write
        _edit = State(initialValue: edit)
    }

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
        .onSubmit { endTheEdit() }
        .onChange(of: isFocused) { _, focused in
            if focused == false { endTheEdit() }
        }
    }

    /// Ends the edit and writes the one value the edit changed.
    func endTheEdit() {
        guard let typed = edit.end(from: text) else { return }
        write(typed)
    }
}
