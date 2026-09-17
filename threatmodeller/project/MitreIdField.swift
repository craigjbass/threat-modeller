import SwiftUI
import ThreatModelKit

/// One MITRE ATT&CK id, or a list of them, picked by search.
///
/// Issue #148 and
/// `docs/superpowers/specs/2026-09-17-mitre-id-field-design.md`: every place
/// the window takes a technique id or a group id takes it here. A person types
/// part of an id or part of a name, the rows under the box state id and name,
/// and a pick becomes a token. The field writes `[String]`: the same list the
/// parser reads, ids only.
///
/// An id the synchronised matrix lacks is kept and marked, because a library
/// may state a technique the matrix version on this machine does not, and the
/// file must round trip.
struct MitreIdField: View {
    /// What the field is for, over the box.
    let title: String
    /// The accessibility identifier of the box. Every other control of this
    /// field builds its identifier from this word.
    let identifier: String
    let kind: AttackSearchKind
    /// True for a list of ids. False holds one id, and a second pick replaces
    /// the first.
    let allowsMany: Bool
    @Binding var ids: [String]
    /// What searches the synchronised data. The session passes the use case.
    let search: (String, AttackSearchKind) -> SearchAttackDataResponse
    /// What brings the matrix onto this machine, or nil when no project holds
    /// this field.
    let synchronise: (() async -> Void)?

    /// What a person has typed into the box.
    @State private var typed: String

    init(
        title: String,
        identifier: String,
        kind: AttackSearchKind = .technique,
        allowsMany: Bool = true,
        ids: Binding<[String]>,
        search: @escaping (String, AttackSearchKind) -> SearchAttackDataResponse,
        synchronise: (() async -> Void)? = nil,
        typed: String = ""
    ) {
        self.title = title
        self.identifier = identifier
        self.kind = kind
        self.allowsMany = allowsMany
        _ids = ids
        self.search = search
        self.synchronise = synchronise
        _typed = State(initialValue: typed)
    }

    // MARK: what the field reads

    /// What the search answers for what is typed.
    private var found: SearchAttackDataResponse { search(typed, kind) }

    /// The rows the list draws: what the words match, less what the field
    /// already holds, so nobody picks one id twice.
    var rows: [AttackSearchRow] { rows(for: typed) }

    /// The rows one set of words matches. The list draws the words a person
    /// typed; a caller that holds its own words passes them.
    func rows(for text: String) -> [AttackSearchRow] {
        let held = Set(ids.map { $0.lowercased() })
        return search(text, kind).rows.filter { held.contains($0.id.lowercased()) == false }
    }

    /// True when this machine holds a synchronised matrix of this kind.
    var holdsData: Bool { found.holdsData }

    /// True while a synchronise can be started from this field.
    var canSynchronise: Bool { synchronise != nil }

    /// One row, as a person reads it: the id and the name.
    static func label(of row: AttackSearchRow) -> String {
        "\(row.id) \(row.name)"
    }

    /// The name the matrix gives this id, or nil when it holds no such id.
    func name(of id: String) -> String? {
        let wanted = id.lowercased()
        return search(id, kind).rows.first { $0.id.lowercased() == wanted }?.name
    }

    /// True when the matrix is here and states no such id. A machine with no
    /// matrix marks nothing, because there is nothing to check against.
    func isUnknown(_ id: String) -> Bool {
        holdsData && name(of: id) == nil
    }

    /// What the field says under the box.
    var says: String {
        guard holdsData else {
            return "This machine holds no synchronised ATT&CK matrix. "
                + "Type an id, or press Synchronise ATT&CK."
        }
        let unknown = ids.filter { isUnknown($0) }
        guard unknown.isEmpty == false else { return "" }
        let named = unknown.joined(separator: ", ")
        return unknown.count == 1
            ? "\(named) is not in the synchronised matrix."
            : "\(named) are not in the synchronised matrix."
    }

    /// What a token says on hover.
    func help(for id: String) -> String {
        if let name = name(of: id) { return name }
        return holdsData
            ? "This id is not in the synchronised matrix."
            : "This machine holds no synchronised matrix, so nothing checks this id."
    }

    // MARK: what the field writes

    /// Takes one row as a token. A single field replaces what it holds.
    func pick(_ row: AttackSearchRow) {
        add(row.id)
        typed = ""
    }

    /// Takes what is typed as a token, whatever the matrix holds. An id the
    /// matrix lacks is kept and marked.
    func commitTyped() {
        let wanted = typed.trimmingCharacters(in: .whitespaces)
        guard wanted.isEmpty == false else { return }
        add(wanted)
        typed = ""
    }

    /// Takes one token off.
    func remove(_ id: String) {
        ids.removeAll { $0 == id }
    }

    private func add(_ id: String) {
        guard allowsMany else {
            ids = [id]
            return
        }
        guard ids.contains(where: { $0.lowercased() == id.lowercased() }) == false else { return }
        ids.append(id)
    }

    // MARK: what the field draws

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)

            if ids.isEmpty == false { tokens }

            TextField(placeholder, text: box)
                .textFieldStyle(.roundedBorder)
                .onSubmit { commitTyped() }
                .onKeyPress(.delete) {
                    guard typed.isEmpty, let last = ids.last else { return .ignored }
                    remove(last)
                    return .handled
                }
                .accessibilityIdentifier(identifier)

            if rows.isEmpty == false { list }

            if says.isEmpty == false { notice }
        }
    }

    /// The box reads and writes the typed word. `TextField` needs a binding,
    /// and the state is this view's own.
    private var box: Binding<String> {
        Binding(get: { typed }, set: { typed = $0 })
    }

    private var placeholder: String {
        kind == .group
            ? "Search the ATT&CK groups by id or by name"
            : "Search the ATT&CK techniques by id or by name"
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
            Text(id)
                .font(.caption.weight(.medium))
            if isUnknown(id) {
                Image(systemName: "questionmark.circle")
                    .font(.caption2)
                    .foregroundStyle(.orange)
            }
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
                .fill(
                    isUnknown(id)
                        ? Color.orange.opacity(0.18)
                        : Color.accentColor.opacity(0.18)
                )
        )
        .help(help(for: id))
        .accessibilityIdentifier("\(identifier)-token-\(id)")
    }

    private var list: some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(rows, id: \.id) { row in
                Button {
                    pick(row)
                } label: {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text(row.id)
                            .font(.caption.monospaced())
                            .frame(minWidth: 72, alignment: .leading)
                        Text(row.name)
                            .font(.caption)
                        Spacer(minLength: 4)
                        if row.isSubTechnique {
                            Text("sub-technique")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .accessibilityIdentifier("\(identifier)-row-\(row.id)")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 6)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
        .accessibilityIdentifier("\(identifier)-rows")
    }

    private var notice: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(says)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("\(identifier)-says")

            if holdsData == false, let synchronise {
                Button("Synchronise ATT&CK") {
                    Task { await synchronise() }
                }
                .buttonStyle(.borderless)
                .accessibilityIdentifier("\(identifier)-synchronise")
            }
        }
    }
}

/// Lays its views out in a row and wraps to the next line when the row is
/// full.
///
/// The tokens of a MITRE id field sit in this. A scrolling row would draw
/// nothing under `ImageRenderer`, which is what the pixel tests use.
struct WrappingRow: Layout {
    var spacing: CGFloat = 4

    func sizeThatFits(
        proposal: ProposedViewSize,
        subviews: Subviews,
        cache: inout ()
    ) -> CGSize {
        let laid = lay(subviews, width: proposal.width ?? .infinity)
        return CGSize(width: proposal.width ?? laid.size.width, height: laid.size.height)
    }

    func placeSubviews(
        in bounds: CGRect,
        proposal: ProposedViewSize,
        subviews: Subviews,
        cache: inout ()
    ) {
        let laid = lay(subviews, width: bounds.width)
        for (index, view) in subviews.enumerated() {
            let point = laid.points[index]
            view.place(
                at: CGPoint(x: bounds.minX + point.x, y: bounds.minY + point.y),
                proposal: .unspecified
            )
        }
    }

    /// Where each view sits, and how much room the whole row takes.
    private func lay(_ subviews: Subviews, width: CGFloat) -> (points: [CGPoint], size: CGSize) {
        var points: [CGPoint] = []
        var across: CGFloat = 0
        var down: CGFloat = 0
        var lineHeight: CGFloat = 0
        var widest: CGFloat = 0

        for view in subviews {
            let size = view.sizeThatFits(.unspecified)
            if across > 0, across + size.width > width {
                across = 0
                down += lineHeight + spacing
                lineHeight = 0
            }
            points.append(CGPoint(x: across, y: down))
            across += size.width + spacing
            widest = max(widest, across - spacing)
            lineHeight = max(lineHeight, size.height)
        }

        return (points, CGSize(width: widest, height: down + lineHeight))
    }
}
