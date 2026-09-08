/// One piece of an architecture or controls file, with where it was found.
///
/// Every fault a user reads names a line and a column, so every token carries
/// them.
public struct Token: Equatable, Sendable {
    public let kind: TokenKind
    /// The value, with the quotes and the escapes already taken off a string.
    public let text: String
    public let line: Int
    public let column: Int

    public init(kind: TokenKind, text: String, line: Int, column: Int) {
        self.kind = kind
        self.text = text
        self.line = line
        self.column = column
    }
}

public enum TokenKind: String, Equatable, Sendable {
    case identifier
    case string
    case number
    case boolean
    case leftBrace
    case rightBrace
    case leftBracket
    case rightBracket
    case equals
    case arrow
    case comma
    case endOfFile
}
