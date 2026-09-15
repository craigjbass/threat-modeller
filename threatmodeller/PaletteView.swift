import SwiftUI
import ThreatModelKit

/// The technology palette: one section per provider, one row per technology.
/// Drag a row onto the canvas, or double-click it.
struct PaletteView: View {
    let session: ThreatModelSession
    /// Deleting a technology deletes the components using it, so the canvas
    /// must drop those rows from its selection.
    let canvas: CanvasState
    /// The project this model sits in, or nil in a document window. A
    /// technology moves into a library only in a project.
    var project: ProjectSession?

    /// nil when no sheet is open, .some(nil) for a new technology, and
    /// .some(id) to change one.
    @State private var editing: EditedTechnology?
    /// What a person typed in the search field.
    @State private var searchText = ""
    /// The technology the keyboard is on, or nil.
    @State private var selected: String?

    /// The palette, narrowed by what a person typed.
    private var shown: [ListedProvider] {
        PaletteSearch.narrow(session.palette, to: searchText)
    }

    /// True while a search is on, so every category with a match is open and
    /// nothing matching stays hidden.
    private var isSearching: Bool {
        searchText.trimmingCharacters(in: .whitespaces).isEmpty == false
    }

    var body: some View {
        List(selection: $selected) {
            ForEach(shown, id: \.id) { provider in
                Section(provider.displayName) {
                    ForEach(provider.categories, id: \.id) { category in
                        CategoryDisclosure(
                            providerId: provider.id,
                            category: category,
                            session: session,
                            canvas: canvas,
                            project: project,
                            isSearching: isSearching,
                            edit: { editing = EditedTechnology(value: $0) }
                        )
                    }
                }
            }
        }
        .searchable(text: $searchText, placement: .sidebar, prompt: "Search technologies")
        // Return places what the arrow keys picked, so the palette has a
        // keyboard path from end to end.
        .onKeyPress(.return) {
            guard let selected else { return .ignored }
            session.addAtDefaultPoint(technologyId: selected)
            return .handled
        }
        .navigationTitle("Technologies")
        // A `safeAreaInset` draws over the scrolled content and paints
        // nothing behind itself, so the rows have to scroll under a bar rather
        // than under a bare button. The selection panels at the bottom of the
        // canvas do the same.
        .safeAreaInset(edge: .bottom, spacing: 0) {
            VStack(spacing: 0) {
                Divider()
                Button {
                    editing = EditedTechnology(value: nil)
                } label: {
                    Label("New Technology\u{2026}", systemImage: "plus")
                        .frame(maxWidth: .infinity)
                }
                .padding(8)
                .accessibilityIdentifier("new-technology")
            }
            .background(.bar)
        }
        .sheet(item: $editing) { technologyId in
            CustomTechnologyEditor(session: session, technologyId: technologyId.value)
        }
    }
}

/// `sheet(item:)` needs something identifiable. A technology being changed is
/// named by its identifier; a new one has no identifier yet.
private struct EditedTechnology: Identifiable {
    let value: String?
    var id: String { value ?? "new" }
}

/// A category row plus its technologies.
///
/// This does not use `DisclosureGroup`. That control treats a click anywhere in
/// its label area as a toggle, so a button inside the label toggled the state a
/// second time and the group never opened. Here one button owns the toggle and
/// the rows below appear when it is open.
private struct CategoryDisclosure: View {
    let providerId: String
    let category: ListedCategory
    let session: ThreatModelSession
    let canvas: CanvasState
    let project: ProjectSession?
    /// True while a person is searching. Every category with a match is open
    /// then, whatever it was before, and it goes back afterwards.
    let isSearching: Bool
    let edit: (String) -> Void

    @State private var isExpanded = false

    private var isOpen: Bool { isSearching || isExpanded }

    var body: some View {
        Group {
            Button {
                isExpanded.toggle()
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: isOpen ? "chevron.down" : "chevron.right")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .frame(width: 10)
                    Text(category.label)
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("category-\(providerId)-\(category.id)")

            if isOpen {
                ForEach(category.technologies, id: \.id) { technology in
                    TechnologyRow(
                        technology: technology,
                        session: session,
                        canvas: canvas,
                        project: project,
                        isDefinedByThisModel: providerId == CustomTechnology.provider.value,
                        edit: edit
                    )
                    .padding(.leading, 16)
                    .tag(technology.id)
                }
            }
        }
    }
}

/// A technology row. Drag it onto the canvas to place it where it is dropped,
/// or double-click it to place it near the top left of the canvas.
struct TechnologyRow: View {
    let technology: ListedTechnology
    let session: ThreatModelSession
    let canvas: CanvasState
    /// The project this model sits in, or nil in a document window.
    var project: ProjectSession?
    /// Only a technology this model defines can be changed or deleted. The
    /// catalogue is a library, and this application does not edit it.
    let isDefinedByThisModel: Bool
    let edit: (String) -> Void

    /// True while the question is on screen. Deleting a technology deletes
    /// every component that uses it, so the question is asked first.
    @State private var isAsking = false
    /// True while the question about which library is on screen.
    @State private var isMoving = false
    /// The library the technology moves into.
    @State private var libraryLabel = "shared"

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(technology.name)
            Text(technology.description)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .help(Self.hover(over: technology))
        .accessibilityIdentifier("technology-\(technology.id)")
        .draggable(technology.id) {
            Text(technology.name)
                .padding(6)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.accentColor.opacity(0.2)))
        }
        .onTapGesture(count: 2) {
            session.addAtDefaultPoint(technologyId: technology.id)
        }
        .contextMenu {
            if isDefinedByThisModel {
                Button("Edit\u{2026}") { edit(technology.id) }
                // A technology in a library is read by every system in the
                // project, and vendored by another project.
                if let project, project.root != nil {
                    Button("Move to Library\u{2026}") { isMoving = true }
                        .accessibilityIdentifier("move-technology-to-library")
                }
                Button("Delete\u{2026}", role: .destructive) { isAsking = true }
            }
        }
        .alert("Move \(technology.name) to a library", isPresented: $isMoving) {
            TextField("Library name", text: $libraryLabel)
                .accessibilityIdentifier("library-label")
            Button("Move") {
                project?.moveTechnologyToLibrary(technology.id, into: libraryLabel)
                isMoving = false
            }
            Button("Cancel", role: .cancel) { isMoving = false }
        } message: {
            Text(
                "The technology moves into <name>.lib in this project's library "
                    + "directory. Every system in the project reads it, and another "
                    + "project vendors it with threatmodeller library add."
            )
        }
        .confirmationDialog(
            "Delete \(technology.name)?",
            isPresented: $isAsking,
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) { delete() }
            Button("Cancel", role: .cancel) { isAsking = false }
        } message: {
            Text(Self.question(name: technology.name, components: componentsUsingIt))
        }
    }

    /// What hovering a technology says: what it is, and what it brings.
    static func hover(over technology: ListedTechnology) -> String {
        let threats = technology.threatCount == 1
            ? "1 threat"
            : "\(technology.threatCount) threats"
        return "\(technology.description)\n\nRaises \(threats)."
    }

    /// How many components on the diagram use this technology.
    private var componentsUsingIt: Int {
        session.canvas.components.filter { $0.technologyId == technology.id }.count
    }

    /// What the question says. A technology nothing uses is still asked about,
    /// because deleting is a change to the file either way.
    static func question(name: String, components: Int) -> String {
        switch components {
        case 0:
            "No component uses \(name). Deleting it removes it from this model."
        case 1:
            "1 component uses \(name). Deleting it removes that component and every "
                + "link that touches it. One undo puts them back."
        default:
            "\(components) components use \(name). Deleting it removes those components "
                + "and every link that touches them. One undo puts them back."
        }
    }

    private func delete() {
        session.deleteCustomTechnology(technology.id)
        canvas.retainOnly(
            componentIds: Set(session.canvas.components.map(\.id)),
            connectionIds: Set(session.canvas.connections.map(\.id)),
            zoneIds: Set(session.canvas.zones.map(\.id))
        )
    }
}
