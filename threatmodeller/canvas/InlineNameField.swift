import SwiftUI

/// A name edited in place, on the element itself.
///
/// Return commits, Escape cancels and changes nothing, and a click elsewhere
/// commits: the field is where a person is looking, so leaving it is the same
/// as pressing Return. One edit is one change, never one per keystroke, which
/// is why the field holds its own text and writes once.
struct InlineNameField: View {
    let text: String
    let width: CGFloat
    let identifier: String
    let commit: (String) -> Void
    let cancel: () -> Void

    @State private var edited: String = ""
    @FocusState private var isFocused: Bool

    var body: some View {
        TextField("Name", text: $edited)
            .textFieldStyle(.roundedBorder)
            .font(.headline)
            .frame(width: width)
            .focused($isFocused)
            .accessibilityIdentifier(identifier)
            .onAppear {
                edited = text
                isFocused = true
            }
            .onSubmit { commit(edited) }
            .onExitCommand { cancel() }
            .onChange(of: isFocused) { _, focused in
                // Clicking elsewhere takes the focus away, and that commits:
                // a person who typed a name and looked away means the name.
                if focused == false { commit(edited) }
            }
    }
}
