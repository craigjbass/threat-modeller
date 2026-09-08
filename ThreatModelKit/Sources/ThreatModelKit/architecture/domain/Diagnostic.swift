/// One fault, where it was found.
///
/// A user reads a fault in an editor or in a build log, and both read
/// `file:line:column: severity: message`.
public struct Diagnostic: Equatable, Sendable {
    public enum Severity: String, Equatable, Sendable {
        case error
        case warning
    }

    public let severity: Severity
    public let line: Int
    public let column: Int
    public let message: String

    public init(severity: Severity, line: Int, column: Int, message: String) {
        self.severity = severity
        self.line = line
        self.column = column
        self.message = message
    }

    public func described(in fileName: String) -> String {
        "\(fileName):\(line):\(column): \(severity.rawValue): \(message)"
    }
}
