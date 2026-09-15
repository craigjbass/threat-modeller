import SwiftUI
import ThreatModelKit

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
    /// True while the index browser is on screen.
    @State private var isBrowsing = false
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
        .sheet(isPresented: $isBrowsing) { indexBrowser }
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

                // A fetch runs `git`, which waits on a server. A person who
                // has waited long enough stops it here.
                Button("Cancel Fetch") { session.cancel() }
                    // Every other control is off while a fetch runs. This one
                    // is the way to stop it, so it stays on.
                    .disabled(false)
                    .accessibilityIdentifier("cancel-fetch")
            }

            // The index is read when a person presses this, never at launch
            // and never when the sheet opens.
            Button("Browse Index\u{2026}") {
                isBrowsing = true
                Task { await session.browseIndex() }
            }
            .help("Read the library index. This reaches a server.")
            .accessibilityIdentifier("library-browse-index")

            Button("Check for Updates") {
                Task { await session.checkForUpdates() }
            }
            .help("Ask each repository which versions it holds. This is the one control here that reaches a server.")
            .accessibilityIdentifier("library-check-for-updates")

            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("libraries-done")
        }
        // Cancel answers while a fetch runs; every other control waits.
        .disabled(session.isWorking)
    }

    /// What the index holds, narrowed by what a person typed.
    private var indexBrowser: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Add a library from the index")
                .font(.headline)

            Text(
                "An entry here is a pointer, not an endorsement. Adding one fetches "
                    + "that repository with your own git."
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            TextField("Search", text: indexSearch, prompt: Text("acme"))
                .textFieldStyle(.roundedBorder)
                .accessibilityIdentifier("library-index-search")

            if session.isReadingIndex {
                ProgressView()
                    .controlSize(.small)
                    .accessibilityIdentifier("library-index-reading")
            } else if session.shownIndexed.isEmpty {
                Text(session.errorMessage ?? "The index lists nothing that matches.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("library-index-empty")
            }

            List(session.shownIndexed, id: \.label) { entry in
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(entry.name)
                        Text(entry.description.isEmpty ? entry.repository : entry.description)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 8)
                    if let tag = entry.newestTag {
                        Text(tag)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    Button("Add") {
                        isBrowsing = false
                        Task { await session.add(indexed: entry) }
                    }
                    .accessibilityIdentifier("library-index-add-\(entry.label)")
                }
                .accessibilityIdentifier("library-index-row-\(entry.label)")
            }
            .frame(minHeight: 220)

            HStack {
                Spacer()
                Button("Cancel") { isBrowsing = false }
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(20)
        .frame(minWidth: 520)
    }

    private var indexSearch: Binding<String> {
        Binding(get: { session.indexSearch }, set: { session.indexSearch = $0 })
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
