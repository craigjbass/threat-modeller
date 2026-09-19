import SwiftUI
import ThreatModelKit

/// One control for a list of ids picked off a fixed set of named choices.
///
/// Issue #179:
/// `docs/superpowers/specs/2026-09-18-id-token-field-design.md`. `Uses`,
/// `Reaches` and `Holds` used to draw a `Menu` of one `Toggle` per choice. A
/// menu closes on every pick, so a person adding three items opened the menu
/// three times, and a menu with a tick per row reads as one choice, not a
/// set.
///
/// This field draws the chosen ids as tokens, each with an icon, a name and a
/// remove control, and an "Add…" control that opens a list a person searches.
/// The list stays open after a pick, so a person picks several choices
/// before closing it. `MitreIdField` searches a few hundred rows and only
/// shows its list while a person is typing a match; this field opens on a
/// small, fixed set the caller already narrowed by system, so the whole list
/// shows even with nothing typed.
struct IdTokenField: View {
    /// One choice the field can add as a token: an id, a name and the SF
    /// Symbol name its token draws.
    struct Choice: Equatable {
        let id: String
        let name: String
        let icon: String
    }

    /// One field's search list: whether it is open, and what a person typed
    /// into it.
    @Observable
    final class Search {
        var isOpen: Bool
        var text: String

        init(isOpen: Bool = false, text: String = "") {
            self.isOpen = isOpen
            self.text = text
        }
    }

    /// What a field says when the system holds no component to pick.
    static let noComponentMessage = "No component to pick yet. Add one on the canvas."

    /// What a field says when the system holds no asset to pick.
    static let noAssetMessage = "No asset to pick yet. Add one in Assets."

    /// The accessibility identifier of the field. Every control this field
    /// draws builds its own identifier from this word.
    let identifier: String
    @Binding var ids: [String]
    /// Every choice the field may add. Empty means the caller's own list of
    /// named things is empty, and the field says so instead of drawing a
    /// control with nothing to offer.
    let choices: [Choice]
    /// What the field says when `choices` is empty.
    let emptyMessage: String

    @State private var search: Search

    init(
        identifier: String,
        ids: Binding<[String]>,
        choices: [Choice],
        emptyMessage: String,
        search: Search = Search()
    ) {
        self.identifier = identifier
        _ids = ids
        self.choices = choices
        self.emptyMessage = emptyMessage
        _search = State(initialValue: search)
    }

    /// True while the search list is open.
    var isOpen: Bool { search.isOpen }

    /// What a person has typed into the search box.
    var typed: String { search.text }

    // MARK: what the field reads

    /// The choices the list offers: every choice not already a token,
    /// narrowed to what is typed, if anything is typed.
    var rows: [Choice] {
        let held = Set(ids)
        let unheld = choices.filter { held.contains($0.id) == false }
        let wanted = search.text.trimmingCharacters(in: .whitespaces).lowercased()
        guard wanted.isEmpty == false else { return unheld }
        return unheld.filter {
            $0.name.lowercased().contains(wanted) || $0.id.lowercased().contains(wanted)
        }
    }

    /// The choice a token draws for one id, or nil when the id names no
    /// current choice.
    func choice(of id: String) -> Choice? {
        choices.first { $0.id == id }
    }

    /// The name a token draws for one id: the choice's name, or the bare id
    /// when `choice(of:)` gives nil.
    func nameForToken(_ id: String) -> String {
        choice(of: id)?.name ?? id
    }

    // MARK: what the field writes

    /// Takes one choice on as a token. The list stays open, so a person
    /// picks the next choice straight away.
    func pick(_ choice: Choice) {
        guard ids.contains(choice.id) == false else { return }
        ids.append(choice.id)
    }

    /// Takes one token off.
    func remove(_ id: String) {
        ids.removeAll { $0 == id }
    }

    /// Opens the search list.
    func open() { search.isOpen = true }

    /// Closes the search list and clears what was typed.
    func close() {
        search.isOpen = false
        search.text = ""
    }

    // MARK: what the field draws

    var body: some View {
        if choices.isEmpty {
            Text(emptyMessage)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("\(identifier)-empty")
        } else {
            VStack(alignment: .leading, spacing: 4) {
                if ids.isEmpty == false { tokens }

                if isOpen {
                    openControl
                } else {
                    Button("Add\u{2026}") { open() }
                        .accessibilityIdentifier("\(identifier)-add")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .accessibilityIdentifier(identifier)
        }
    }

    private var tokens: some View {
        WrappingRow(spacing: 4) {
            ForEach(ids, id: \.self) { id in
                token(id)
            }
        }
    }

    private func token(_ id: String) -> some View {
        HStack(spacing: 3) {
            Image(systemName: choice(of: id)?.icon ?? "questionmark.circle")
                .font(.caption2)
            Text(nameForToken(id))
                .font(.caption.weight(.medium))
            Button {
                remove(id)
            } label: {
                Image(systemName: "xmark")
                    .font(.caption2)
            }
            .buttonStyle(.borderless)
            .accessibilityIdentifier("\(identifier)-remove-\(id)")
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(
            RoundedRectangle(cornerRadius: 4)
                .fill(Color.accentColor.opacity(0.18))
        )
        .accessibilityIdentifier("\(identifier)-token-\(id)")
    }

    private var typedBinding: Binding<String> {
        Binding(get: { search.text }, set: { search.text = $0 })
    }

    private var openControl: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                TextField("Search", text: typedBinding)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("\(identifier)-search")
                Button("Close") { close() }
                    .accessibilityIdentifier("\(identifier)-close")
            }
            if rows.isEmpty == false { list }
        }
    }

    // MARK: choices built from the model

    /// A component's token draws its shape: a person for an actor, a
    /// cylinder for a store, a circle for a process.
    static func choice(forComponent component: ViewedComponent) -> Choice {
        let icon: String
        switch DiagramShape(rawValue: component.shapeId) {
        case .actor: icon = "person.fill"
        case .store: icon = "cylinder.fill"
        case .process, .none: icon = "circle.fill"
        }
        return Choice(id: component.id, name: component.name, icon: icon)
    }

    /// An asset carries no shape of its own, so every asset's token draws
    /// the same icon.
    static func choice(forAsset asset: ViewedSystemAsset) -> Choice {
        Choice(id: asset.id, name: asset.name, icon: "archivebox.fill")
    }

    private var list: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(rows, id: \.id) { choice in
                Button {
                    pick(choice)
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: choice.icon)
                            .font(.caption)
                        Text(choice.name)
                            .font(.caption)
                        Spacer(minLength: 4)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .accessibilityIdentifier("\(identifier)-row-\(choice.id)")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .accessibilityIdentifier("\(identifier)-rows")
    }
}
