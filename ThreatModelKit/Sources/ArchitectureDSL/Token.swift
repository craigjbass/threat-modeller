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
    /// How many characters the token takes in the file, from its column.
    ///
    /// A string drops its quotation marks and its escapes on the way into
    /// `text`, so the count of `text` is not the count in the file. An editor
    /// colours by the count in the file.
    public let length: Int

    public init(kind: TokenKind, text: String, line: Int, column: Int, length: Int? = nil) {
        self.kind = kind
        self.text = text
        self.line = line
        self.column = column
        self.length = length ?? text.count
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
    /// A comment. The parse drops it; highlighting keeps it.
    case comment
    case endOfFile
}
