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
    /// What a person typed in the search field. A test states one to open the
    /// palette mid-search.
    @State private var searchText: String

    init(
        session: ThreatModelSession,
        canvas: CanvasState,
        project: ProjectSession? = nil,
        searchText: String = ""
    ) {
        self.session = session
        self.canvas = canvas
        self.project = project
        _searchText = State(initialValue: searchText)
    }
    /// The technology the keyboard is on, or nil.
    @State private var selected: String?

    var body: some View {
        // The button sits under the list, not in a `safeAreaInset`. An inset
        // over a `List` in a sidebar column drew its bar and took no press:
        // the scroll view under it answered every click. A sibling in a stack
        // owns its own hits.
        VStack(spacing: 0) {
            PaletteList(
                session: session,
                canvas: canvas,
                project: project,
                searchText: searchText,
                selected: $selected,
                edit: { editing = EditedTechnology(value: $0) }
            )

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
        .searchable(text: $searchText, placement: .sidebar, prompt: "Search technologies")
        .navigationTitle("Technologies")
        .sheet(item: $editing) { technologyId in
            CustomTechnologyEditor(session: session, technologyId: technologyId.value)
        }
    }
}

/// The rows the palette draws, narrowed by what a person typed.
///
/// It is its own view so a test drives the narrowing without a search field,
/// and so the list is diffed in place the way it is while a person types.
struct PaletteList: View {
    let session: ThreatModelSession
    let canvas: CanvasState
    var project: ProjectSession?
    let searchText: String
    @Binding var selected: String?
    let edit: (String) -> Void

    /// The palette, narrowed by what a person typed.
    private var shown: [ListedProvider] {
        PaletteSearch.narrow(session.palette, to: searchText)
    }

    /// True while a search is on, so every category with a match is open and
    /// nothing matching stays hidden.
    private var isSearching: Bool {
        searchText.trimmingCharacters(in: .whitespaces).isEmpty == false
    }

    /// Every row the narrowed list holds, so a selection naming a row that
    /// has left can be dropped.
    private var shownIds: Set<String> {
        Set(PaletteSearch.technologies(of: shown).map(\.id))
    }

    /// Which categories a person has opened. It lives here rather than in
    /// each row, because a row that leaves the list must not take the state
    /// with it. A test states the set to open the palette part way.
    @State var openCategories: Set<String> = []

    /// True while the User row is on the list: always, until a search names
    /// something else.
    private var showsUser: Bool {
        PaletteSearch.showsUser(for: searchText)
    }

    var body: some View {
        List(selection: $selected) {
            // A user is not a technology, so the row sits in its own section
            // above every provider. The user block design states it.
            if showsUser {
                Section("Users") {
                    UserRow(session: session)
                        .tag(ThreatModelSession.userDropId)
                }
            }
            ForEach(shown, id: \.id) { provider in
                Section(provider.displayName) {
                    // One flat sequence of identified rows, never a `Group`
                    // holding a conditional. AppKit constrains a section's
                    // header to its first row, and a row sequence whose
                    // structure changes under it left the two in different
                    // hierarchies: `NSGenericException: Unable to activate
                    // constraint … no common ancestor`.
                    ForEach(rows(of: provider), id: \.id) { row in
                        switch row.kind {
                        case .category(let category):
                            CategoryRow(
                                providerId: provider.id,
                                category: category,
                                isOpen: isOpen(provider.id, category.id),
                                toggle: { toggle(provider.id, category.id) }
                            )
                        case .technology(let technology, let providerId):
                            TechnologyRow(
                                technology: technology,
                                session: session,
                                canvas: canvas,
                                project: project,
                                isDefinedByThisModel:
                                    providerId == CustomTechnology.provider.value,
                                edit: edit
                            )
                            .padding(.leading, 16)
                            .tag(technology.id)
                        }
                    }
                }
            }
        }
        // A list keeps a selection by its row's key. A narrowing that takes
        // that row away leaves the list holding a key nothing draws, so the
        // selection is dropped as the rows go.
        .onChange(of: searchText) { _, _ in
            guard let selected else { return }
            if selected == ThreatModelSession.userDropId {
                if showsUser == false { self.selected = nil }
            } else if shownIds.contains(selected) == false {
                self.selected = nil
            }
        }
        // Return places what the arrow keys picked, so the palette has a
        // keyboard path from end to end.
        .onKeyPress(.return) {
            guard let selected else { return .ignored }
            session.addAtDefaultPoint(technologyId: selected)
            return .handled
        }
    }

    /// Every row one provider draws: each category, and under an open one its
    /// technologies.
    private func rows(of provider: ListedProvider) -> [PaletteRow] {
        provider.categories.flatMap { category -> [PaletteRow] in
            let header = PaletteRow(
                id: "category:\(provider.id):\(category.id)",
                kind: .category(category)
            )
            guard isOpen(provider.id, category.id) else { return [header] }
            return [header] + category.technologies.map { technology in
                PaletteRow(
                    id: "technology:\(provider.id):\(category.id):\(technology.id)",
                    kind: .technology(technology, provider.id)
                )
            }
        }
    }

    /// True while a category shows its technologies. Every category with a
    /// match is open while a search is on, and goes back afterwards.
    private func isOpen(_ providerId: String, _ categoryId: String) -> Bool {
        isSearching || openCategories.contains("\(providerId):\(categoryId)")
    }

    private func toggle(_ providerId: String, _ categoryId: String) {
        let key = "\(providerId):\(categoryId)"
        if openCategories.contains(key) {
            openCategories.remove(key)
        } else {
            openCategories.insert(key)
        }
    }
}

/// The palette's User row. Drag it onto the canvas to put a user where it
/// is dropped, or double-click it to put one near the top left of the
/// canvas. A user is a human with no technology; the canvas draws it with the
/// actor shape and the save writes a `user` block.
struct UserRow: View {
    let session: ThreatModelSession

    static let name = "User"
    static let description = "A person who uses the system: a role, an access level and what they reach"

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(Self.name)
            Text(Self.description)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .help("\(Self.description)\n\nRaises no threats. May be a threat actor.")
        .accessibilityIdentifier("palette-user")
        .draggable(ThreatModelSession.userDropId) {
            Text(Self.name)
                .padding(6)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.accentColor.opacity(0.2)))
        }
        .simultaneousGesture(TapGesture(count: 2).onEnded {
            session.addAtDefaultPoint(technologyId: ThreatModelSession.userDropId)
        })
    }
}

/// One row of the palette: a category a person opens, or a technology.
struct PaletteRow: Identifiable {
    enum Kind {
        case category(ListedCategory)
        case technology(ListedTechnology, String)
    }

    let id: String
    let kind: Kind
}

/// A category's own row.
///
/// This does not use `DisclosureGroup`. That control treats a click anywhere
/// in its label area as a toggle, so a button inside the label toggled the
/// state a second time and the group never opened. Here one button owns the
/// toggle and the rows the list draws under it come from the list itself.
private struct CategoryRow: View {
    let providerId: String
    let category: ListedCategory
    let isOpen: Bool
    let toggle: () -> Void

    var body: some View {
        Button(action: toggle) {
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
    }
}

/// `sheet(item:)` needs something identifiable. A technology being changed is
/// named by its identifier; a new one has no identifier yet.
private struct EditedTechnology: Identifiable {
    let value: String?
    var id: String { value ?? "new" }
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
        .simultaneousGesture(TapGesture(count: 2).onEnded {
            session.addAtDefaultPoint(technologyId: technology.id)
        })
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
