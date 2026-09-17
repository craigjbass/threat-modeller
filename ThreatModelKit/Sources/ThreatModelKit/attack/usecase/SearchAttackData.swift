import Foundation

public protocol SearchAttackDataUseCase {
    func execute(_ request: SearchAttackDataRequest) -> SearchAttackDataResponse
}

/// Which part of the synchronised data a search reads.
public enum AttackSearchKind: String, Equatable, Sendable, CaseIterable {
    case technique
    case group
}

/// One row a search answers: the id a file holds, and the name beside it.
public struct AttackSearchRow: Equatable, Sendable {
    public let id: String
    public let name: String
    /// True for a sub-technique, so a row can state it. Always false for a
    /// group.
    public let isSubTechnique: Bool

    public init(id: String, name: String, isSubTechnique: Bool = false) {
        self.id = id
        self.name = name
        self.isSubTechnique = isSubTechnique
    }
}

public struct SearchAttackDataRequest: Equatable, Sendable {
    /// What a person typed.
    public let text: String
    public let kind: AttackSearchKind
    /// How many rows to answer. A field draws a short list, so a person who
    /// typed one letter reads the best few rather than eight hundred.
    public let limit: Int

    public init(text: String, kind: AttackSearchKind = .technique, limit: Int = 12) {
        self.text = text
        self.kind = kind
        self.limit = limit
    }
}

public struct SearchAttackDataResponse: Equatable, Sendable {
    public let rows: [AttackSearchRow]
    /// True when this machine holds data of that kind. False states that
    /// nobody has synchronised, and the field says how to.
    public let holdsData: Bool

    public init(rows: [AttackSearchRow], holdsData: Bool) {
        self.rows = rows
        self.holdsData = holdsData
    }
}

/// Searches the synchronised ATT&CK data by id and by name.
///
/// Issue #148 and
/// `docs/superpowers/specs/2026-09-17-mitre-id-field-design.md`: the window
/// picks a MITRE id from this list rather than taking one typed from memory.
///
/// It reads the two files in the data directory through `MitreActorSource`,
/// which keeps what it read, so a search costs one parse per run of the
/// application and a filter per keystroke. No network call, no project.
public struct SearchAttackData: SearchAttackDataUseCase {
    private let mitre: MitreActorSource

    public init(mitre: MitreActorSource) {
        self.mitre = mitre
    }

    public func execute(_ request: SearchAttackDataRequest) -> SearchAttackDataResponse {
        let wanted = request.text.trimmingCharacters(in: .whitespaces).lowercased()

        switch request.kind {
        case .technique:
            let held = mitre.techniques()
            return answer(
                rows: held.map {
                    Ranked(
                        row: AttackSearchRow(
                            id: $0.id,
                            name: $0.name,
                            isSubTechnique: $0.isSubTechnique
                        ),
                        aliases: []
                    )
                },
                wanted: wanted,
                limit: request.limit,
                holdsData: held.isEmpty == false
            )
        case .group:
            let held = mitre.groups()
            return answer(
                rows: held.map {
                    Ranked(
                        row: AttackSearchRow(id: $0.attackId, name: $0.name),
                        aliases: $0.aliases
                    )
                },
                wanted: wanted,
                limit: request.limit,
                holdsData: held.isEmpty == false
            )
        }
    }

    /// One row of the data, with the words a search matches it by.
    private struct Ranked {
        let row: AttackSearchRow
        let aliases: [String]
    }

    private func answer(
        rows: [Ranked],
        wanted: String,
        limit: Int,
        holdsData: Bool
    ) -> SearchAttackDataResponse {
        guard wanted.isEmpty == false else {
            return SearchAttackDataResponse(rows: [], holdsData: holdsData)
        }

        let matched = rows.compactMap { held -> (Int, AttackSearchRow)? in
            guard let rank = Self.rank(held, wanted) else { return nil }
            return (rank, held.row)
        }
        // The rank sorts best first, and the id sorts two rows of one rank, so
        // the same words give the same list every time.
        let sorted = matched
            .sorted { first, second in
                first.0 == second.0 ? first.1.id < second.1.id : first.0 < second.0
            }
            .map(\.1)

        return SearchAttackDataResponse(
            rows: Array(sorted.prefix(max(0, limit))),
            holdsData: holdsData
        )
    }

    /// How well one row matches the words, lower being better, and nil when it
    /// does not match at all. The design states the table.
    private static func rank(_ held: Ranked, _ wanted: String) -> Int? {
        let id = held.row.id.lowercased()
        let name = held.row.name.lowercased()

        if id == wanted { return 0 }
        if id.hasPrefix(wanted) { return 1 }
        if name.hasPrefix(wanted) { return 2 }
        if name.contains(wanted) { return 3 }
        if held.aliases.contains(where: { $0.lowercased().contains(wanted) }) { return 4 }
        return nil
    }
}
