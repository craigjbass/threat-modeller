import ThreatModelKit

/// Reads a file as tokens.
///
/// It never throws and never stops. A character it does not know is one fault
/// and one skipped character, so a file with two faults reports two.
public struct Lexer {
    private let characters: [Character]

    public init(_ text: String) {
        characters = Array(text)
    }

    /// The tokens, and the faults found while reading them.
    ///
    /// A parse drops a comment. Highlighting colours one, so
    /// `keepingComments` asks for a `.comment` token in the same walk.
    public func scan(keepingComments: Bool = false) -> (tokens: [Token], faults: [Diagnostic]) {
        var tokens: [Token] = []
        var faults: [Diagnostic] = []
        var index = 0
        var line = 1
        var column = 1

        func advance(_ steps: Int = 1) {
            for _ in 0 ..< steps where index < characters.count {
                if characters[index] == "\n" {
                    line += 1
                    column = 1
                } else {
                    column += 1
                }
                index += 1
            }
        }

        while index < characters.count {
            let character = characters[index]

            if character == "\n" || character == " " || character == "\t" || character == "\r" {
                advance()
                continue
            }

            let startLine = line
            let startColumn = column
            let startIndex = index

            /// How many characters the token read so far takes in the file.
            func length() -> Int { index - startIndex }

            // A comment runs to the end of the line. The writer does not put
            // comments back, so the parse drops one and highlighting keeps
            // one.
            if character == "#" || (character == "/" && peek(index + 1) == "/") {
                while index < characters.count && characters[index] != "\n" { advance() }
                if keepingComments {
                    tokens.append(
                        Token(
                            kind: .comment,
                            text: String(characters[startIndex ..< index]),
                            line: startLine,
                            column: startColumn,
                            length: length()
                        )
                    )
                }
                continue
            }

            if character == "\"" {
                advance()
                var value = ""
                var isClosed = false
                while index < characters.count {
                    let inner = characters[index]
                    if inner == "\\" , index + 1 < characters.count {
                        value.append(Self.unescaped(characters[index + 1]))
                        advance(2)
                        continue
                    }
                    if inner == "\"" {
                        advance()
                        isClosed = true
                        break
                    }
                    if inner == "\n" { break }
                    value.append(inner)
                    advance()
                }
                if isClosed {
                    tokens.append(
                        Token(
                            kind: .string,
                            text: value,
                            line: startLine,
                            column: startColumn,
                            length: length()
                        )
                    )
                } else {
                    faults.append(
                        Diagnostic(
                            severity: .error,
                            line: startLine,
                            column: startColumn,
                            message: "this text has no closing quotation mark"
                        )
                    )
                }
                continue
            }

            if character == "<" && peek(index + 1) == "<" {
                advance(2)
                var tag = ""
                while index < characters.count,
                      characters[index].isLetter
                        || characters[index].isNumber
                        || characters[index] == "_" {
                    tag.append(characters[index])
                    advance()
                }
                guard tag.isEmpty == false else {
                    faults.append(
                        Diagnostic(
                            severity: .error,
                            line: startLine,
                            column: startColumn,
                            message: "a heredoc starts \"<<\" and a tag, as in \"<<EOT\""
                        )
                    )
                    continue
                }
                while index < characters.count && characters[index] != "\n" { advance() }
                if index < characters.count { advance() }

                var body = ""
                var isClosed = false
                var lineText = ""
                while index < characters.count {
                    let inner = characters[index]
                    advance()
                    if inner == "\n" {
                        if lineText.trimmedForHeredoc() == tag {
                            isClosed = true
                            break
                        }
                        body += lineText + "\n"
                        lineText = ""
                        continue
                    }
                    lineText.append(inner)
                }
                if isClosed == false && lineText.trimmedForHeredoc() == tag {
                    isClosed = true
                }
                guard isClosed else {
                    faults.append(
                        Diagnostic(
                            severity: .error,
                            line: startLine,
                            column: startColumn,
                            message: "this heredoc has no closing \"\(tag)\" line"
                        )
                    )
                    continue
                }
                tokens.append(
                    Token(
                        kind: .string,
                        text: body,
                        line: startLine,
                        column: startColumn,
                        length: length()
                    )
                )
                continue
            }

            if character == "-" && peek(index + 1) == ">" {
                advance(2)
                tokens.append(
                    Token(
                        kind: .arrow,
                        text: "->",
                        line: startLine,
                        column: startColumn,
                        length: length()
                    )
                )
                continue
            }

            if character.isNumber || (character == "-" && (peek(index + 1)?.isNumber ?? false)) {
                var value = String(character)
                advance()
                while index < characters.count, characters[index].isNumber {
                    value.append(characters[index])
                    advance()
                }
                if index < characters.count, characters[index] == ".",
                   peek(index + 1)?.isNumber ?? false {
                    value.append(".")
                    advance()
                    while index < characters.count, characters[index].isNumber {
                        value.append(characters[index])
                        advance()
                    }
                }
                tokens.append(
                    Token(
                        kind: .number,
                        text: value,
                        line: startLine,
                        column: startColumn,
                        length: length()
                    )
                )
                continue
            }

            if character.isLetter || character == "_" {
                var value = ""
                while index < characters.count,
                      characters[index].isLetter
                        || characters[index].isNumber
                        || characters[index] == "_"
                        || characters[index] == "-" {
                    value.append(characters[index])
                    advance()
                }
                let kind: TokenKind = (value == "true" || value == "false") ? .boolean : .identifier
                tokens.append(
                    Token(
                        kind: kind,
                        text: value,
                        line: startLine,
                        column: startColumn,
                        length: length()
                    )
                )
                continue
            }

            if let punctuation = Self.punctuation[character] {
                advance()
                tokens.append(
                    Token(
                        kind: punctuation,
                        text: String(character),
                        line: startLine,
                        column: startColumn,
                        length: length()
                    )
                )
                continue
            }

            advance()
            faults.append(
                Diagnostic(
                    severity: .error,
                    line: startLine,
                    column: startColumn,
                    message: "this file cannot hold the character \"\(character)\""
                )
            )
        }

        tokens.append(Token(kind: .endOfFile, text: "", line: line, column: column))
        return (tokens, faults)
    }

    private func peek(_ at: Int) -> Character? {
        at < characters.count ? characters[at] : nil
    }

    private static let punctuation: [Character: TokenKind] = [
        "{": .leftBrace,
        "}": .rightBrace,
        "[": .leftBracket,
        "]": .rightBracket,
        "=": .equals,
        ",": .comma
    ]

    private static func unescaped(_ character: Character) -> Character {
        switch character {
        case "n": "\n"
        case "t": "\t"
        default: character
        }
    }
}

private extension String {
    func trimmedForHeredoc() -> String {
        var characters = Array(self)
        while characters.first?.isWhitespace == true { characters.removeFirst() }
        while characters.last?.isWhitespace == true { characters.removeLast() }
        return String(characters)
    }
}
