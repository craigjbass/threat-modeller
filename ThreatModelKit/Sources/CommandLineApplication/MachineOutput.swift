import Foundation
import ThreatModelKit

/// How a verb writes what it found.
///
/// `plain` is what a person reads in a terminal, and it is what every verb
/// wrote before this existed. `github` is what a GitHub Actions job reads, so
/// a pull request shows the line rather than a red check with no word on it.
/// `json` is what any other tool reads.
public enum MachineOutput: String, CaseIterable, Sendable {
    case plain
    case github
    case json

    /// The format that word names, or nil when it names none.
    public static func named(_ word: String) -> MachineOutput? {
        MachineOutput(rawValue: word)
    }

    public static var names: String {
        allCases.map(\.rawValue).joined(separator: "|")
    }
}

/// The GitHub Actions workflow-command shapes.
///
/// A job reads `::error file=…,line=…,col=…::<message>` and puts it on the
/// pull request beside the line it names.
public enum GitHubOutput {
    public static func line(
        severity: Diagnostic.Severity,
        file: String,
        line: Int,
        column: Int,
        message: String
    ) -> String {
        let word = severity == .error ? "error" : "warning"
        return "::\(word) file=\(file),line=\(line),col=\(column)::\(escaped(message))"
    }

    public static func line(_ diagnostic: Diagnostic, in file: String) -> String {
        line(
            severity: diagnostic.severity,
            file: file,
            line: diagnostic.line,
            column: diagnostic.column,
            message: diagnostic.message
        )
    }

    /// A workflow command ends at a newline, and `%` starts an escape, so
    /// those three characters travel encoded.
    static func escaped(_ message: String) -> String {
        message
            .replacingOccurrences(of: "%", with: "%25")
            .replacingOccurrences(of: "\r", with: "%0D")
            .replacingOccurrences(of: "\n", with: "%0A")
    }
}

/// Where a threat's answer sits in a `.controls` file.
///
/// A pull request shows a message beside a line, so an unanswered threat names
/// the line of its own stanza. A file that holds no stanza for it names line 1,
/// which is the file itself.
public enum ControlsStanzaLines {
    public static func line(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        in text: String?
    ) -> Int {
        guard let text else { return 1 }
        let wanted = "threat \"\(threatId)\" on \(sourceKind) \"\(sourceId)\""

        for (index, line) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated()
        where line.contains(wanted) {
            return index + 1
        }
        return 1
    }
}

/// What `check` found in one system, for the `json` format.
public struct CheckedSystemJSON: Codable, Equatable, Sendable {
    public struct DiagnosticJSON: Codable, Equatable, Sendable {
        public let severity: String
        public let file: String
        public let line: Int
        public let column: Int
        public let message: String
    }

    public struct UnansweredJSON: Codable, Equatable, Sendable {
        public let threatId: String
        public let sourceKind: String
        public let sourceId: String
        public let riskLevel: String
        public let file: String
        public let line: Int
    }

    public let name: String
    public let tolerance: String
    public let diagnostics: [DiagnosticJSON]
    public let unanswered: [UnansweredJSON]
    public let stale: [String]
    public let staleTrees: [String]
    /// What an accepted risk has not stated: no entry, no owner, no review
    /// date, or a review date that has passed.
    public let governance: [String]
}

/// Everything one `check` run found.
public struct CheckReportJSON: Codable, Equatable, Sendable {
    public let systems: [CheckedSystemJSON]
    /// What the run said about the project rather than about one system: a
    /// catalogue that would not load, a library warning, a directory that
    /// holds no `.arch` file.
    public let messages: [String]

    /// One object, pretty-printed with sorted keys, so two runs of one project
    /// write the same bytes and a diff of one line is one line.
    public func text() -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(self) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }
}
