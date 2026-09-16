import ArchitectureDSL
import CatalogueGateways
import Foundation
import ThreatModelKit

/// Speaks the Language Server Protocol for the source languages.
///
/// The four languages are written in a text editor, and the editor knows
/// nothing about them: a technology id gets no completion, a wrong control
/// name is found by `check` after the save, and the parser's diagnostics show
/// nowhere. The parsers already carry a line and a column, so this hands them
/// to the editor at the place they belong.
///
/// The server is text in and text out: one message, a list of messages back.
/// A test drives it with a fake client and no pipe.
public final class LanguageServer: @unchecked Sendable {
    /// What a document is: its text, and which language it holds.
    enum Language: String {
        case architecture = "arch"
        case controls
        case library = "lib"
        case attackTree = "attacktree"
        case governance
        case policy = "hcl"

        /// The language a file name holds, or nil for a file this server does
        /// not read.
        static func of(_ uri: String) -> Language? {
            guard let dot = uri.lastIndex(of: ".") else { return nil }
            return Language(rawValue: String(uri[uri.index(after: dot)...]))
        }
    }

    private let projects: ProjectSourceGateway
    private let makeCatalogue: () throws -> TechnologyCatalogue
    private var documents: [String: String] = [:]
    private var catalogue: TechnologyCatalogue?

    public init(
        projects: ProjectSourceGateway,
        catalogue: @escaping () throws -> TechnologyCatalogue = { try BundledTechnologyCatalogue() }
    ) {
        self.projects = projects
        makeCatalogue = catalogue
    }

    /// One message from the client, and everything to write back: an answer,
    /// a diagnostics notification, or both.
    public func answer(to line: String) -> [String] {
        guard let data = line.data(using: .utf8),
              let request = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let method = request["method"] as? String else {
            return [Self.error(id: nil, code: -32700, message: "the message is not JSON")]
        }
        let id = request["id"]
        let parameters = request["params"] as? [String: Any] ?? [:]

        switch method {
        case "initialize":
            return [Self.result(id: id, Self.capabilities)]
        case "initialized", "exit", "$/cancelRequest":
            return []
        case "shutdown":
            return [Self.result(id: id, NSNull())]
        case "textDocument/didOpen":
            let document = parameters["textDocument"] as? [String: Any] ?? [:]
            let uri = document["uri"] as? String ?? ""
            documents[uri] = document["text"] as? String ?? ""
            return [diagnostics(of: uri)]
        case "textDocument/didChange":
            let document = parameters["textDocument"] as? [String: Any] ?? [:]
            let uri = document["uri"] as? String ?? ""
            let changes = parameters["contentChanges"] as? [[String: Any]] ?? []
            // The server states full sync, so the last change is the document.
            documents[uri] = changes.last?["text"] as? String ?? documents[uri] ?? ""
            return [diagnostics(of: uri)]
        case "textDocument/didSave", "textDocument/didClose":
            let uri = (parameters["textDocument"] as? [String: Any])?["uri"] as? String ?? ""
            if method.hasSuffix("didClose") { documents[uri] = nil; return [] }
            return [diagnostics(of: uri)]
        case "textDocument/completion":
            return [Self.result(id: id, completions(at: parameters))]
        case "textDocument/hover":
            return [Self.result(id: id, hover(at: parameters))]
        case "textDocument/definition":
            return [Self.result(id: id, definition(at: parameters))]
        case "textDocument/formatting":
            return [Self.result(id: id, formatting(of: parameters))]
        case "textDocument/semanticTokens/full":
            return [Self.result(id: id, semanticTokens(at: parameters))]
        default:
            guard id != nil else { return [] }
            return [Self.error(id: id, code: -32601, message: "there is no method \"\(method)\"")]
        }
    }

    /// What this server does, as the protocol states it.
    static var capabilities: [String: Any] {
        [
            "capabilities": [
                // 1 is full sync: the client sends the whole document on a
                // change.
                "textDocumentSync": 1,
                "completionProvider": ["triggerCharacters": ["\"", " ", "="]],
                "hoverProvider": true,
                "definitionProvider": true,
                "documentFormattingProvider": true,
                "semanticTokensProvider": [
                    "legend": [
                        "tokenTypes": Self.tokenTypes,
                        "tokenModifiers": [String]()
                    ],
                    "full": true
                ]
            ],
            "serverInfo": ["name": "threatmodeller", "version": "1.0.0"]
        ]
    }

    // MARK: semantic tokens

    /// The token types this server colours, in the order the legend states
    /// them. A client reads a token's type as an index into this list.
    static let tokenTypes = ["keyword", "string", "number", "comment", "operator", "variable"]

    private enum TokenType: Int {
        case keyword = 0
        case string = 1
        case number = 2
        case comment = 3
        case `operator` = 4
        case variable = 5
    }

    /// Every token of one document, encoded the way the protocol states it.
    ///
    /// A document in a language this server does not read answers an empty
    /// array, and so does an empty document.
    func semanticTokens(at parameters: [String: Any]) -> [String: Any] {
        let uri = (parameters["textDocument"] as? [String: Any])?["uri"] as? String ?? ""
        guard Language.of(uri) != nil else { return ["data": [Int]()] }
        return ["data": Self.encoded(documents[uri] ?? "")]
    }

    /// The lexer's tokens as five numbers each: the lines down from the token
    /// before, the characters across from the token before, the length, the
    /// type, and the modifiers.
    ///
    /// The lexer reads every language this server reads, so one walk colours
    /// all six. A file the parser rejects still holds tokens, so a person
    /// mid-edit keeps the colour.
    static func encoded(_ text: String) -> [Int] {
        let lengths = text.split(separator: "\n", omittingEmptySubsequences: false)
            .map(\.count)
        let tokens = Lexer(text).scan(keepingComments: true).tokens
        var data: [Int] = []
        var lastLine = 0
        var lastColumn = 0

        for (index, token) in tokens.enumerated() {
            let before = index > 0 ? tokens[index - 1] : nil
            let after = index + 1 < tokens.count ? tokens[index + 1] : nil
            guard let type = type(of: token, after: before, before: after) else { continue }
            // The protocol counts from zero and the lexer counts from one.
            let line = token.line - 1
            let column = token.column - 1
            guard line >= 0, column >= 0, line < lengths.count else { continue }
            // The protocol states that a token stays on one line, and a
            // heredoc does not, so a token stops at the end of its own line.
            let length = min(token.length, lengths[line] - column)
            guard length > 0 else { continue }
            data += [
                line - lastLine,
                line == lastLine ? column - lastColumn : column,
                length,
                type.rawValue,
                0
            ]
            lastLine = line
            lastColumn = column
        }
        return data
    }

    /// The type one token takes, or nil for a token an editor colours itself.
    ///
    /// A brace, a bracket, an equals sign and a comma get no type: every
    /// editor already draws punctuation.
    private static func type(of token: Token, after before: Token?, before after: Token?)
        -> TokenType? {
        switch token.kind {
        case .comment: .comment
        case .number: .number
        case .boolean: .keyword
        case .arrow: .operator
        case .identifier:
            // A flow names two components beside the arrow. Every other word
            // is a block name or an attribute name.
            (before?.kind == .arrow || after?.kind == .arrow) ? .variable : .keyword
        case .string:
            // A block header states its label straight after a word, as in
            // `component "api"`. An attribute and a list state a text after
            // an equals sign, a bracket or a comma.
            before?.kind == .identifier ? .variable : .string
        default: nil
        }
    }

    // MARK: the parser's own diagnostics

    /// Every fault the parser found, at the line and the column it states.
    /// The protocol counts from zero and the parsers count from one.
    func diagnostics(of uri: String) -> String {
        let found = read(documents[uri] ?? "", as: Language.of(uri))
        let published = found.map { diagnostic -> [String: Any] in
            let line = max(0, diagnostic.line - 1)
            let column = max(0, diagnostic.column - 1)
            return [
                "range": [
                    "start": ["line": line, "character": column],
                    "end": ["line": line, "character": column + 1]
                ],
                "severity": diagnostic.severity == .error ? 1 : 2,
                "source": "threatmodeller",
                "message": diagnostic.message
            ]
        }
        return Self.notification(
            "textDocument/publishDiagnostics",
            ["uri": uri, "diagnostics": published]
        )
    }

    /// The faults one text holds, read by the language it is written in.
    private func read(_ text: String, as language: Language?) -> [Diagnostic] {
        switch language {
        case .architecture: HclArchitectureSource().read(text).diagnostics
        case .controls: HclControlsSource().read(text).diagnostics
        case .library: HclLibrarySource().read(text).diagnostics
        case .attackTree: HclAttackTreeSource().read(text).diagnostics
        case .governance: HclGovernanceSource().read(text).diagnostics
        case .policy: HclPolicySource().read(text).diagnostics
        case nil: []
        }
    }

    // MARK: completion

    /// What a person may type here.
    func completions(at parameters: [String: Any]) -> [String: Any] {
        let uri = (parameters["textDocument"] as? [String: Any])?["uri"] as? String ?? ""
        let text = documents[uri] ?? ""
        let language = Language.of(uri)
        let position = parameters["position"] as? [String: Any] ?? [:]
        let lineNumber = position["line"] as? Int ?? 0
        let character = position["character"] as? Int ?? 0

        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let line = lineNumber < lines.count ? lines[lineNumber] : ""
        let before = String(line.prefix(character))
        let trimmedBefore = before.trimmingCharacters(in: .whitespaces)

        var items: [[String: Any]] = []

        if before.contains("technology") {
            items += every(technology: catalogueNow()).map {
                item($0.id.value, kind: 6, detail: "\($0.name) — \($0.description)")
            }
        } else if trimmedBefore.hasPrefix("flow") || before.contains("->") {
            items += componentIds(in: text).map { item($0, kind: 6, detail: "a component") }
        } else if before.contains("threat ") {
            items += everyThreat(catalogueNow()).map {
                item($0.id.value, kind: 6, detail: "\($0.name) (\($0.severity.label))")
            }
        } else if before.contains("control ") {
            items += controlsOfThreat(above: lineNumber, in: lines).map {
                item($0, kind: 1, detail: "a control this threat offers")
            }
        } else if before.contains("zone") || before.contains("boundary") {
            items += zoneIds(in: text).map { item($0, kind: 6, detail: "a zone") }
        }

        // An attribute of the block the cursor sits in. A person typing a word
        // at the start of a line is naming an attribute.
        if before.trimmingCharacters(in: .whitespaces).contains(" ") == false {
            items += Self.attributes(of: block(above: lineNumber, in: lines), language: language)
                .map { item($0, kind: 10, detail: "an attribute") }
        }

        return ["isIncomplete": false, "items": items]
    }

    private func item(_ label: String, kind: Int, detail: String) -> [String: Any] {
        ["label": label, "kind": kind, "detail": detail]
    }

    /// The attributes each block holds, so an editor offers the word rather
    /// than the person reading the language guide.
    static func attributes(of block: String, language: Language?) -> [String] {
        switch (language, block) {
        case (.architecture, "system"):
            [
                "catalogue", "owner", "description", "authors", "links", "repositories",
                "created", "reviewed", "version", "risk_tolerance",
                "requires_evidence_above", "faces"
            ]
        case (.architecture, "component"):
            ["technology", "name", "zone", "data", "status", "holds", "provided_by", "source",
             "threats", "runs_as", "shape", "tags"]
        case (.architecture, "zone"):
            ["kind", "network", "name", "reduces_risk", "reduces_risk_by", "boundary",
             "description", "source", "tags"]
        case (.architecture, "flow"):
            ["kind", "description", "carries", "tags"]
        case (.architecture, "asset"):
            ["name", "classification", "description", "owner"]
        case (.architecture, "third_party"):
            ["name", "description", "kind", "paying_customer", "uptime", "uptime_notes",
             "owner", "link"]
        case (.architecture, "mitigates"):
            ["threats", "reduces_risk_by", "status"]
        case (.controls, "threat"):
            ["severity", "score", "impacts"]
        case (.controls, "control"):
            ["status", "note", "evidence", "says"]
        case (.library, "threat"):
            ["name", "description", "severity", "stride", "impacts", "connection", "zone",
             "zone_context", "applies_to", "boundary", "runs_as", "pathway", "likelihood"]
        case (.library, "technology"):
            ["name", "category", "description", "threats", "encrypts"]
        case (.governance, "accepted"), (.governance, "work"):
            ["owner", "accepted_on", "review_by", "due_by", "rationale", "effort", "status"]
        case (.policy, _):
            PolicySource.ruleNames + PolicySource.settingNames
        default:
            []
        }
    }

    /// The block the cursor sits in, by the nearest opening line above it.
    func block(above line: Int, in lines: [String]) -> String {
        var depth = 0
        var index = min(line, lines.count) - 1
        while index >= 0 {
            let text = lines[index].trimmingCharacters(in: .whitespaces)
            if text.hasSuffix("}") && text.hasPrefix("{") == false { depth += 1 }
            if text.hasSuffix("{") {
                if depth == 0 {
                    return text.split(separator: " ").first.map(String.init) ?? ""
                }
                depth -= 1
            }
            index -= 1
        }
        return ""
    }

    /// The controls the threat above this line offers, from the catalogue.
    private func controlsOfThreat(above line: Int, in lines: [String]) -> [String] {
        var index = min(line, lines.count) - 1
        while index >= 0 {
            let text = lines[index].trimmingCharacters(in: .whitespaces)
            if text.hasPrefix("threat ") || text.hasPrefix("stale threat ") {
                guard let id = Self.firstQuoted(in: text) else { return [] }
                return everyThreat(catalogueNow())
                    .first { $0.id.value == id }?
                    .controls.map(\.description) ?? []
            }
            index -= 1
        }
        return []
    }

    // MARK: hover

    /// What the word under the cursor means.
    func hover(at parameters: [String: Any]) -> Any {
        let uri = (parameters["textDocument"] as? [String: Any])?["uri"] as? String ?? ""
        let text = documents[uri] ?? ""
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let position = parameters["position"] as? [String: Any] ?? [:]
        let lineNumber = position["line"] as? Int ?? 0
        guard lineNumber < lines.count else { return NSNull() }
        let line = lines[lineNumber]
        guard let word = Self.firstQuoted(in: line) else { return NSNull() }

        if let technology = catalogueNow()?.findById(TechnologyId(word)) {
            let threats = catalogueNow()?.threatsFor(technologyId: technology.id) ?? []
            let said = ([
                "**\(technology.name)** (`\(technology.id.value)`)",
                "",
                technology.description,
                "",
                "Raises \(threats.count) threats:"
            ] + threats.map { "- \($0.id.value): \($0.name) (\($0.severity.label))" })
                .joined(separator: "\n")
            return ["contents": ["kind": "markdown", "value": said]]
        }

        // A threat stanza in a `.controls` file states its own score.
        if line.trimmingCharacters(in: .whitespaces).hasPrefix("threat "),
           Language.of(uri) == .controls {
            var score: String?
            var severity: String?
            var index = lineNumber + 1
            while index < lines.count {
                let inner = lines[index].trimmingCharacters(in: .whitespaces)
                if inner == "}" { break }
                if inner.hasPrefix("score") { score = inner.split(separator: "=").last.map {
                    $0.trimmingCharacters(in: .whitespaces)
                } }
                if inner.hasPrefix("severity") { severity = Self.firstQuoted(in: inner) }
                index += 1
            }
            let value = Int(score ?? "") ?? 0
            let level = RiskScore(value: value).level.label
            return [
                "contents": [
                    "kind": "markdown",
                    "value": "**\(word)** — score \(value), level \(level)"
                        + (severity.map { ", severity \($0)" } ?? "")
                ]
            ]
        }

        if let threat = everyThreat(catalogueNow()).first(where: { $0.id.value == word }) {
            return [
                "contents": [
                    "kind": "markdown",
                    "value": "**\(threat.name)** (`\(threat.id.value)`)\n\n\(threat.description)"
                        + "\n\nSeverity \(threat.severity.label)."
                ]
            ]
        }

        return NSNull()
    }

    // MARK: go to definition

    /// Where the thing under the cursor is declared.
    func definition(at parameters: [String: Any]) -> Any {
        let uri = (parameters["textDocument"] as? [String: Any])?["uri"] as? String ?? ""
        let text = documents[uri] ?? ""
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let position = parameters["position"] as? [String: Any] ?? [:]
        let lineNumber = position["line"] as? Int ?? 0
        guard lineNumber < lines.count else { return NSNull() }
        let line = lines[lineNumber]

        // A component named in a flow is declared in this same document.
        if line.trimmingCharacters(in: .whitespaces).hasPrefix("flow ") {
            let character = position["character"] as? Int ?? 0
            let named = Self.wordAt(character, in: line)
            if let found = Self.line(declaring: "component", named: named, in: lines) {
                return Self.location(uri: uri, line: found)
            }
        }

        // A technology a library declares, in whichever `.lib` the project
        // holds it in.
        guard let word = Self.firstQuoted(in: line) ?? Self.wordAt(
            position["character"] as? Int ?? 0,
            in: line
        ) as String? else { return NSNull() }

        if let found = Self.line(declaring: "component", named: word, in: lines) {
            return Self.location(uri: uri, line: found)
        }

        for path in libraryPaths() {
            guard let libraryText = try? projects.read(path: path) else { continue }
            let libraryLines = libraryText
                .split(separator: "\n", omittingEmptySubsequences: false)
                .map(String.init)
            // A library's ids carry the provider prefix; the file states them
            // without it.
            let bare = word.contains("-")
                ? String(word[word.index(after: word.firstIndex(of: "-")!)...])
                : word
            for name in [word, bare] {
                if let found = Self.line(declaring: "technology", named: name, in: libraryLines) {
                    return Self.location(uri: "file://\(path)", line: found)
                }
                if let found = Self.line(declaring: "threat", named: name, in: libraryLines) {
                    return Self.location(uri: "file://\(path)", line: found)
                }
            }
        }

        return NSNull()
    }

    private func libraryPaths() -> [String] {
        guard let uri = documents.keys.first,
              let root = Self.root(of: uri),
              let layout = try? projects.discover(root: root) else { return [] }
        return layout.libraryPaths
    }

    /// The project a file sits in: the directory above `threatmodel/`.
    static func root(of uri: String) -> String? {
        let path = uri.hasPrefix("file://") ? String(uri.dropFirst("file://".count)) : uri
        guard let range = path.range(
            of: "/\(ProjectConvention.conventionDirectoryName)/"
        ) else { return nil }
        return String(path[path.startIndex ..< range.lowerBound])
    }

    // MARK: formatting

    /// The document, written again by the writer `format` uses.
    func formatting(of parameters: [String: Any]) -> Any {
        let uri = (parameters["textDocument"] as? [String: Any])?["uri"] as? String ?? ""
        let text = documents[uri] ?? ""
        guard let language = Language.of(uri) else { return NSNull() }

        let written: String?
        switch language {
        case .architecture:
            let source = HclArchitectureSource()
            written = source.read(text).source.map(source.write)
        case .controls:
            let source = HclControlsSource()
            written = source.read(text).source.map(source.write)
        case .library:
            let source = HclLibrarySource()
            written = source.read(text).source.map(source.write)
        case .attackTree:
            let source = HclAttackTreeSource()
            written = source.read(text).source.map(source.write)
        case .governance, .policy:
            // These two are written by a person and by `compile`; this server
            // states no canonical shape for them.
            written = nil
        }
        guard let written, written != text else { return [] }

        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        return [
            [
                "range": [
                    "start": ["line": 0, "character": 0],
                    "end": ["line": lines.count, "character": 0]
                ],
                "newText": written
            ]
        ]
    }

    // MARK: what the catalogue holds

    private func catalogueNow() -> TechnologyCatalogue? {
        if let catalogue { return catalogue }
        catalogue = try? makeCatalogue()
        return catalogue
    }

    private func every(technology catalogue: TechnologyCatalogue?) -> [Technology] {
        catalogue?.all() ?? []
    }

    private func everyThreat(_ catalogue: TechnologyCatalogue?) -> [Threat] {
        guard let catalogue else { return [] }
        var found = catalogue.connectionThreats() + catalogue.zoneThreats()
        for technology in catalogue.all() {
            found += catalogue.threatsFor(technologyId: technology.id)
        }
        var seen: Set<String> = []
        return found.filter { seen.insert($0.id.value).inserted }
    }

    // MARK: reading the text

    /// The component ids this document declares.
    func componentIds(in text: String) -> [String] {
        Self.declared("component", in: text)
    }

    /// The zone ids this document declares.
    func zoneIds(in text: String) -> [String] {
        Self.declared("zone", in: text)
    }

    static func declared(_ keyword: String, in text: String) -> [String] {
        text.split(separator: "\n", omittingEmptySubsequences: false)
            .compactMap { line in
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard trimmed.hasPrefix("\(keyword) \"") else { return nil }
                return firstQuoted(in: trimmed)
            }
    }

    /// The line a block of this kind and this name opens on, counting from
    /// zero, or nil when the text declares none.
    static func line(declaring keyword: String, named: String, in lines: [String]) -> Int? {
        lines.firstIndex { line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            return trimmed.hasPrefix("\(keyword) \"") && firstQuoted(in: trimmed) == named
        }
    }

    static func location(uri: String, line: Int) -> [String: Any] {
        [
            "uri": uri,
            "range": [
                "start": ["line": line, "character": 0],
                "end": ["line": line, "character": 0]
            ]
        ]
    }

    /// What stands between the first pair of quotation marks.
    static func firstQuoted(in line: String) -> String? {
        guard let open = line.firstIndex(of: "\"") else { return nil }
        let rest = line[line.index(after: open)...]
        guard let close = rest.firstIndex(of: "\"") else { return nil }
        return String(rest[rest.startIndex ..< close])
    }

    /// The word the cursor sits in, taking a letter, a digit, a dash and an
    /// underscore as part of a word.
    static func wordAt(_ character: Int, in line: String) -> String {
        let letters = Array(line)
        guard letters.isEmpty == false else { return "" }
        var start = min(character, letters.count - 1)
        func isWord(_ one: Character) -> Bool {
            one.isLetter || one.isNumber || one == "-" || one == "_"
        }
        guard isWord(letters[start]) else { return "" }
        while start > 0 && isWord(letters[start - 1]) { start -= 1 }
        var end = start
        while end + 1 < letters.count && isWord(letters[end + 1]) { end += 1 }
        return String(letters[start ... end])
    }

    // MARK: JSON-RPC

    static func result(id: Any?, _ value: Any) -> String {
        write(["jsonrpc": "2.0", "id": id ?? NSNull(), "result": value])
    }

    static func error(id: Any?, code: Int, message: String) -> String {
        write([
            "jsonrpc": "2.0",
            "id": id ?? NSNull(),
            "error": ["code": code, "message": message]
        ])
    }

    static func notification(_ method: String, _ value: [String: Any]) -> String {
        write(["jsonrpc": "2.0", "method": method, "params": value])
    }

    private static func write(_ value: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(
            withJSONObject: value,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ) else {
            return "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"unwritable\"}}"
        }
        return String(decoding: data, as: UTF8.self)
    }
}
