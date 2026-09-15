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
    /// The file this fault is in, when the reader knows it. A merged read of a
    /// split system sets it, so a fault in one file names that file rather
    /// than the system.
    public let file: String?

    public init(
        severity: Severity,
        line: Int,
        column: Int,
        message: String,
        file: String? = nil
    ) {
        self.severity = severity
        self.line = line
        self.column = column
        self.message = message
        self.file = file
    }

    /// The same fault, in that file.
    public func `in`(file: String) -> Diagnostic {
        Diagnostic(
            severity: severity,
            line: line,
            column: column,
            message: message,
            file: file
        )
    }

    /// `file:line:column: severity: message`, the shape a person and a build
    /// log read. The fault's own file wins over the one the caller passes.
    public func described(in fileName: String) -> String {
        "\(file ?? fileName):\(line):\(column): \(severity.rawValue): \(message)"
    }
}
