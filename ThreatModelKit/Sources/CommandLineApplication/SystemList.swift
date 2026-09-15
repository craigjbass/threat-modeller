import Foundation
import ThreatModelKit

/// One row of `threatmodeller list`: what one system is and what it scores.
///
/// A project holding thirty systems is read here rather than in thirty
/// reports. A system whose files do not parse still takes a row, holding its
/// name, its file and the word `unparsed`: `check` is the verb that fails,
/// and a list that drops a system hides it.
public struct SystemRow: Equatable, Sendable {
    public let name: String
    public let file: String
    public let owner: String
    public let components: Int
    public let zones: Int
    public let flows: Int
    public let threats: Int
    public let unanswered: Int
    public let accepted: Int
    public let worstScore: Int
    public let worstLevel: String
    public let catalogueTag: String
    public let reviewed: String
    /// True when the system's files did not parse, so every number above is
    /// unknown rather than zero.
    public let isUnparsed: Bool

    public init(
        name: String,
        file: String,
        owner: String = "",
        components: Int = 0,
        zones: Int = 0,
        flows: Int = 0,
        threats: Int = 0,
        unanswered: Int = 0,
        accepted: Int = 0,
        worstScore: Int = 0,
        worstLevel: String = "",
        catalogueTag: String = "",
        reviewed: String = "",
        isUnparsed: Bool = false
    ) {
        self.name = name
        self.file = file
        self.owner = owner
        self.components = components
        self.zones = zones
        self.flows = flows
        self.threats = threats
        self.unanswered = unanswered
        self.accepted = accepted
        self.worstScore = worstScore
        self.worstLevel = worstLevel
        self.catalogueTag = catalogueTag
        self.reviewed = reviewed
        self.isUnparsed = isUnparsed
    }

    /// The word this row states for one field, or nil when no field has that
    /// name. An unparsed system states `unparsed` for every number.
    public func value(of field: SystemList.Field) -> String {
        switch field {
        case .name: return name
        case .file: return file
        case .owner: return isUnparsed ? SystemList.unparsed : owner
        case .components: return number(components)
        case .zones: return number(zones)
        case .flows: return number(flows)
        case .threats: return number(threats)
        case .unanswered: return number(unanswered)
        case .accepted: return number(accepted)
        case .worstScore: return number(worstScore)
        case .worstLevel: return isUnparsed ? SystemList.unparsed : worstLevel
        case .catalogue: return isUnparsed ? SystemList.unparsed : catalogueTag
        case .reviewed: return isUnparsed ? SystemList.unparsed : reviewed
        }
    }

    private func number(_ value: Int) -> String {
        isUnparsed ? SystemList.unparsed : String(value)
    }
}

/// What `threatmodeller list` writes, and how.
public enum SystemList {
    /// What an unparsed system states in place of a number.
    public static let unparsed = "unparsed"

    /// The columns, in the order the plain output writes them when nobody
    /// names any.
    public enum Field: String, CaseIterable, Sendable {
        case name
        case file
        case owner
        case components
        case zones
        case flows
        case threats
        case unanswered
        case accepted
        case worstScore = "worst"
        case worstLevel = "level"
        case catalogue
        case reviewed

        /// What the header states.
        public var heading: String {
            switch self {
            case .worstScore: "WORST"
            case .worstLevel: "LEVEL"
            default: rawValue.uppercased()
            }
        }

        /// True when the column holds a number, so the plain output puts it
        /// to the right.
        var isNumber: Bool {
            switch self {
            case .components, .zones, .flows, .threats, .unanswered, .accepted, .worstScore:
                true
            default:
                false
            }
        }

        public static var names: String {
            allCases.map(\.rawValue).joined(separator: ", ")
        }
    }

    /// The rows as a person reads them: one row per system, the columns
    /// spaced so the numbers line up.
    public static func plain(
        _ rows: [SystemRow],
        fields: [Field],
        wantsHeader: Bool
    ) -> [String] {
        guard fields.isEmpty == false else { return [] }

        var table: [[String]] = []
        if wantsHeader { table.append(fields.map(\.heading)) }
        for row in rows { table.append(fields.map { row.value(of: $0) }) }

        var widths = [Int](repeating: 0, count: fields.count)
        for line in table {
            for (index, cell) in line.enumerated() {
                widths[index] = max(widths[index], cell.count)
            }
        }

        return table.map { line in
            line.enumerated()
                .map { index, cell in
                    let padding = String(repeating: " ", count: widths[index] - cell.count)
                    return fields[index].isNumber ? padding + cell : cell + padding
                }
                .joined(separator: "  ")
                .trimmingTrailingSpaces()
        }
    }

    /// The same rows as an array a dashboard reads. Keys are written in
    /// alphabetical order, so two runs on one project are the same bytes.
    public static func json(_ rows: [SystemRow], fields: [Field]) -> String {
        let objects = rows.map { row in
            Dictionary(uniqueKeysWithValues: fields.map { field in
                (field.rawValue, jsonValue(of: row, field: field))
            })
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = (try? encoder.encode(objects)) ?? Data("[]".utf8)
        return String(decoding: data, as: UTF8.self)
    }

    /// A number stays a number in JSON, so a dashboard sorts on it. An
    /// unparsed system states null rather than a number nobody measured.
    private static func jsonValue(of row: SystemRow, field: Field) -> JsonValue {
        if field.isNumber {
            return row.isUnparsed ? .none : .number(Int(row.value(of: field)) ?? 0)
        }
        return .text(row.value(of: field))
    }

    /// One cell, as JSON writes it.
    enum JsonValue: Encodable {
        case text(String)
        case number(Int)
        case none

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .text(let value): try container.encode(value)
            case .number(let value): try container.encode(value)
            case .none: try container.encodeNil()
            }
        }
    }

    /// The rows in the order one field states. A field holding a number sorts
    /// worst first, because a person asking for the worst reads the top; a
    /// field holding words sorts alphabetically.
    public static func sorted(_ rows: [SystemRow], by field: Field) -> [SystemRow] {
        rows.sorted { left, right in
            if field.isNumber {
                let first = Int(left.value(of: field)) ?? -1
                let second = Int(right.value(of: field)) ?? -1
                if first != second { return first > second }
                return left.name < right.name
            }
            let first = left.value(of: field)
            let second = right.value(of: field)
            if first != second { return first < second }
            return left.name < right.name
        }
    }

    /// The fields a person named, or nil with the word that names none.
    public static func fields(named words: String) -> Result<[Field], String> {
        var picked: [Field] = []
        for word in words.split(separator: ",").map({ String($0).trimmingWhitespaceHere() })
        where word.isEmpty == false {
            guard let field = Field(rawValue: word) else { return .failure(word) }
            picked.append(field)
        }
        return picked.isEmpty ? .failure("") : .success(picked)
    }

    /// What a caller asked for, or what stopped it.
    public enum Result<Held, Fault> {
        case success(Held)
        case failure(Fault)
    }
}

private extension String {
    func trimmingTrailingSpaces() -> String {
        var characters = Array(self)
        while characters.last == " " { characters.removeLast() }
        return String(characters)
    }

    func trimmingWhitespaceHere() -> String {
        var characters = Array(self)
        while characters.first?.isWhitespace == true { characters.removeFirst() }
        while characters.last?.isWhitespace == true { characters.removeLast() }
        return String(characters)
    }
}
