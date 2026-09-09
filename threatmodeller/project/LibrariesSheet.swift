import SwiftUI

/// The shared element libraries a project holds, and what a user does with
/// them.
///
/// Every button calls the use case its `threatmodeller library` verb calls, so
/// the window and the command line cannot disagree about what Add means.
struct LibrariesSheet: View {
    let session: LibrarySession
    let dismiss: () -> Void

    @State private var selected: String?
    @State private var isAdding = false
    @State private var repository = ""
    @State private var tag = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Libraries")
                .font(.title2)

            Text(
                "A library holds technologies and threats your team shares. "
                    + "Every system in this project reads every library."
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            list

            if let message = session.errorMessage {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("library-error")
            }

            if let systems = session.removalInUse {
                removalQuestion(systems)
            }

            controls
        }
        .padding(20)
        .frame(minWidth: 720, minHeight: 420)
        .sheet(isPresented: $isAdding) { addForm }
        .accessibilityIdentifier("libraries-sheet")
    }

    @ViewBuilder
    private var list: some View {
        if session.libraries.isEmpty {
            ContentUnavailableView(
                "No libraries",
                systemImage: "books.vertical",
                description: Text("Add one to share technologies and threats across your projects.")
            )
            .frame(maxWidth: .infinity, minHeight: 200)
        } else {
            Table(session.libraries, selection: selection) {
                TableColumn("Name") { Text($0.name) }
                TableColumn("Library") { Text($0.label).monospaced() }
                TableColumn("Repository") { Text($0.repository).truncationMode(.head) }
                TableColumn("Version") { Text($0.tag).monospaced() }
                TableColumn("Status") { row in
                    Text(status(row))
                        .foregroundStyle(row.matchesLock && row.newestTag == nil ? .secondary : .primary)
                }
            }
            .frame(minHeight: 200)
            .accessibilityIdentifier("library-list")
        }
    }

    private func status(_ row: LibraryRow) -> String {
        if row.matchesLock == false { return "Does not match the lock file" }
        if let newest = row.newestTag { return "\(newest) is newer" }
        if let reason = row.reason { return reason }
        return "Matches"
    }

    private func removalQuestion(_ systems: [String]) -> some View {
        HStack(spacing: 12) {
            Text(
                "\(systems.joined(separator: ", ")) still use this library. "
                    + "Remove it anyway?"
            )
            .font(.callout)

            Spacer(minLength: 8)

            Button("Cancel") { session.cancelRemoval() }
                .accessibilityIdentifier("library-cancel-removal")

            Button("Remove Anyway", role: .destructive) {
                if let label = selected { session.remove(label: label, isForced: true) }
            }
            .accessibilityIdentifier("library-force-remove")
        }
        .padding(10)
        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
    }

    private var controls: some View {
        HStack(spacing: 12) {
            Button("Add\u{2026}") {
                repository = ""
                tag = ""
                isAdding = true
            }
            .accessibilityIdentifier("library-add")

            Button("Update") {
                guard let label = selected else { return }
                Task { await session.update(label: label) }
            }
            .disabled(selected == nil)
            .accessibilityIdentifier("library-update")

            Button("Remove") {
                guard let label = selected else { return }
                session.remove(label: label, isForced: false)
            }
            .disabled(selected == nil)
            .accessibilityIdentifier("library-remove")

            Spacer(minLength: 8)

            if session.isWorking {
                ProgressView()
                    .controlSize(.small)
                    .accessibilityIdentifier("library-working")
            }

            Button("Check for Updates") {
                Task { await session.checkForUpdates() }
            }
            .help("Ask each repository which versions it holds. This is the one control here that reaches a server.")
            .accessibilityIdentifier("library-check-for-updates")

            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("libraries-done")
        }
        .disabled(session.isWorking)
    }

    private var addForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add a library")
                .font(.headline)

            Text("Anything your own git can read works, including a private repository.")
                .font(.caption)
                .foregroundStyle(.secondary)

            TextField("Repository", text: $repository, prompt: Text("git@github.com:acme/threat-elements.git"))
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("library-repository")

            TextField("Version", text: $tag, prompt: Text("v2.1.0"))
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("library-tag")

            HStack {
                Spacer()
                Button("Cancel") { isAdding = false }
                Button("Add") {
                    let wantedRepository = repository
                    let wantedTag = tag
                    isAdding = false
                    Task { await session.add(repository: wantedRepository, tag: wantedTag) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(repository.isEmpty || tag.isEmpty)
                .accessibilityIdentifier("library-add-confirm")
            }
        }
        .padding(20)
        .frame(minWidth: 480)
    }

    private var selection: Binding<String?> {
        Binding(get: { selected }, set: { selected = $0 })
    }
}
