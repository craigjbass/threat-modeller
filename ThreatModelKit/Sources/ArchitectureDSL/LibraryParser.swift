import ThreatModelKit

/// Turns tokens into a `LibrarySource`.
///
/// Like the other two parsers it never throws and never stops at the first
/// fault. On a token it did not expect it records one diagnostic and skips to
/// the next block boundary, so a file with four faults reports four.
struct LibraryParser {
    private let tokens: [Token]
    private var index = 0
    private var diagnostics: [Diagnostic]

    init(tokens: [Token], faults: [Diagnostic]) {
        self.tokens = tokens
        diagnostics = faults
    }

    mutating func parse() -> LibraryRead {
        guard let source = parseLibrary() else {
            return LibraryRead(source: nil, diagnostics: diagnostics)
        }
        check(source)
        return LibraryRead(
            source: diagnostics.contains { $0.severity == .error } ? nil : source,
            diagnostics: diagnostics
        )
    }

    // MARK: the blocks

    private mutating func parseLibrary() -> LibrarySource? {
        guard expectKeyword("library") else { return nil }
        guard let label = expect(.string, "the library's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var displayName: String?
        var catalogueTag: String?
        var technologies: [SourceTechnology] = []
        var threats: [SourceLibraryThreat] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name":
                displayName = parseTextAttribute()
            case "catalogue":
                catalogueTag = parseTextAttribute()
            case "technology":
                if let technology = parseTechnology() { technologies.append(technology) }
            case "threat":
                if let threat = parseThreat() { threats.append(threat) }
            default:
                record(
                    "a library holds name, catalogue, technology and threat, "
                        + "not \"\(current.text)\""
                )
                skipToNextBlock()
            }
        }
        _ = expect(.rightBrace, "}")

        return LibrarySource(
            label: label.text,
            displayName: displayName,
            catalogueTag: catalogueTag,
            technologies: technologies,
            threats: threats
        )
    }

    /// The block the architecture language holds, read the same way, so a
    /// technology reads the same in both files.
    private mutating func parseTechnology() -> SourceTechnology? {
        advance()
        guard let id = expect(.string, "the technology's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var category: String?
        var description = ""
        var threatIds: [String] = []
        var encrypts = false

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "category": category = parseTextAttribute()
            case "description": description = parseTextAttribute() ?? ""
            case "threats": threatIds = parseListAttribute()
            case "encrypts": encrypts = parseBooleanAttribute() ?? false
            default:
                record(
                    "a technology holds name, category, description, threats and encrypts, "
                        + "not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let name else {
            record("the technology \"\(id.text)\" has no name", at: id)
            return nil
        }
        guard let category else {
            record("the technology \"\(id.text)\" has no category", at: id)
            return nil
        }
        return SourceTechnology(
            id: id.text,
            name: name,
            category: category,
            description: description,
            threatIds: threatIds,
            encrypts: encrypts
        )
    }

    private mutating func parseThreat() -> SourceLibraryThreat? {
        nil
    }

    // MARK: what the file must hold once it parses

    private mutating func check(_ source: LibrarySource) {
    }

    // MARK: the attributes

    private mutating func parseTextAttribute() -> String? {
        advance()
        guard expect(.equals, "=") != nil else { return nil }
        return expect(.string, "a text in quotation marks")?.text
    }

    private mutating func parseBooleanAttribute() -> Bool? {
        advance()
        guard expect(.equals, "=") != nil else { return nil }
        return expect(.boolean, "true or false")?.text == "true"
    }

    private mutating func parseListAttribute() -> [String] {
        advance()
        guard expect(.equals, "=") != nil else { return [] }
        guard expect(.leftBracket, "[") != nil else { return [] }

        var values: [String] = []
        while current.kind != .rightBracket && current.kind != .endOfFile {
            if current.kind == .comma { advance(); continue }
            guard let token = expect(.string, "a text in quotation marks") else { break }
            values.append(token.text)
        }
        _ = expect(.rightBracket, "]")
        return values
    }

    // MARK: reading the token list

    private var current: Token { tokens[min(index, tokens.count - 1)] }

    private mutating func advance() {
        if index < tokens.count - 1 { index += 1 }
    }

    private mutating func expectKeyword(_ keyword: String) -> Bool {
        guard current.kind == .identifier, current.text == keyword else {
            record("this file starts with \(keyword), not \"\(current.text)\"")
            return false
        }
        advance()
        return true
    }

    private mutating func expect(_ kind: TokenKind, _ what: String) -> Token? {
        guard current.kind == kind else {
            record("expected \(what)")
            return nil
        }
        let token = current
        advance()
        return token
    }

    private mutating func record(
        _ message: String,
        at token: Token? = nil,
        severity: Diagnostic.Severity = .error
    ) {
        let where_ = token ?? current
        diagnostics.append(
            Diagnostic(
                severity: severity,
                line: where_.line,
                column: where_.column,
                message: message
            )
        )
    }

    /// After a fault, skip forward to somewhere a block can start again, so one
    /// fault does not become ten.
    private mutating func skipToNextBlock() {
        var depth = 0
        while current.kind != .endOfFile {
            if current.kind == .leftBrace { depth += 1 }
            if current.kind == .rightBrace {
                if depth == 0 { return }
                depth -= 1
                advance()
                if depth == 0 { return }
                continue
            }
            advance()
        }
    }

    private mutating func skipAttribute() {
        advance()
        if current.kind == .equals {
            advance()
            if current.kind == .leftBracket {
                while current.kind != .rightBracket && current.kind != .endOfFile { advance() }
            }
            advance()
        } else if current.kind == .leftBrace {
            skipToNextBlock()
        }
    }
}
