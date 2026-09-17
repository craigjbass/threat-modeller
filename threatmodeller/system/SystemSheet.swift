import SwiftUI
import ThreatModelKit

/// The one shape every System sheet takes.
///
/// `docs/superpowers/specs/2026-09-16-system-menu-and-sheets-design.md` states
/// it: a heading and one sentence at the top, the list on the left, the form on
/// the right, and a footer that names the file the sheet writes. Escape closes
/// the sheet, and Cmd+S writes what the form holds.
struct SystemSheet<Entries: View, Form: View>: View {
    let kind: SystemSheetKind
    /// One sentence that says what this sheet states.
    let says: String
    /// The file the sheet writes, by name.
    let fileName: String
    /// True while the form holds enough to write.
    let isWritable: Bool
    /// True while the form holds an entry a person opened with Edit.
    let isEditing: Bool
    let dismiss: () -> Void
    let write: () -> Void
    @ViewBuilder let entries: () -> Entries
    @ViewBuilder let form: () -> Form

    /// How wide the list on the left is. The form takes the rest.
    static var listWidth: Double { 300 }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(kind.title)
                .font(.headline)
            Text(says)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack(alignment: .top, spacing: 12) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        entries()
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(width: Self.listWidth)
                .accessibilityIdentifier("\(kind.rawValue)-list")

                Divider()

                ScrollView {
                    VStack(alignment: .leading, spacing: 8) {
                        form()
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .accessibilityIdentifier("\(kind.rawValue)-form")
            }
            .frame(maxHeight: .infinity)

            footer
        }
        .padding(20)
        .frame(minWidth: 760, minHeight: 520)
        .accessibilityIdentifier("\(kind.rawValue)-sheet")
    }

    private var footer: some View {
        SystemSheetFooter(
            kind: kind,
            fileName: fileName,
            isWritable: isWritable,
            isEditing: isEditing,
            dismiss: dismiss,
            write: write
        )
    }
}

/// The row at the foot of every System sheet: the file the sheet writes,
/// Close on Escape, and the write button on Cmd+S, in that order.
struct SystemSheetFooter: View {
    let kind: SystemSheetKind
    let fileName: String
    let isWritable: Bool
    let isEditing: Bool
    let dismiss: () -> Void
    let write: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            Text("This writes \(fileName).")
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("\(kind.rawValue)-file")

            Spacer(minLength: 8)

            Button("Close") { dismiss() }
                .keyboardShortcut(.cancelAction)
                .accessibilityIdentifier("close-\(kind.rawValue)")

            Button(isEditing ? "Save" : "Add", action: write)
                .keyboardShortcut("s", modifiers: .command)
                .disabled(isWritable == false)
                .accessibilityIdentifier("save-\(kind.rawValue)")
        }
    }
}

/// One row of a System sheet's list: what the entry states, then Edit and
/// Remove at the trailing edge, in that order, in every sheet.
struct SystemSheetRow<Content: View>: View {
    let identifier: String
    let edit: () -> Void
    let remove: () -> Void
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                VStack(alignment: .leading, spacing: 2) {
                    content()
                }
                Spacer(minLength: 4)
                Button {
                    edit()
                } label: {
                    Image(systemName: "pencil")
                }
                .buttonStyle(.borderless)
                .help("Read this entry into the form.")
                .accessibilityIdentifier("edit-\(identifier)")

                Button {
                    remove()
                } label: {
                    Image(systemName: "trash")
                }
                .buttonStyle(.borderless)
                .help("Take this entry off the file.")
                .accessibilityIdentifier("remove-\(identifier)")
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .controlBackgroundColor)))
        .accessibilityIdentifier("row-\(identifier)")
    }
}

/// What a sheet says when its list holds nothing.
struct SystemSheetEmptyNote: View {
    let says: String

    var body: some View {
        Text(says)
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}
