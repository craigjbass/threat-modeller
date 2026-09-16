import ThreatModelKit

/// Turns tokens into a `GovernanceSource`.
///
/// Like the other four parsers it never throws and never stops at the first
/// fault, and it keeps its own copy of the token helpers, which is the shape
/// every parser in this target has.
struct GovernanceParser {
    private let tokens: [Token]
    private var index = 0
    private var diagnostics: [Diagnostic]

    init(tokens: [Token], faults: [Diagnostic]) {
        self.tokens = tokens
        diagnostics = faults
    }

    private static let sourceKinds: Set<String> = ["component", "zone", "flow"]

    /// Every block the file states, whatever the parser recorded about it.
    /// A repair reads this: a file the parser refuses still holds every
    /// attribute a person wrote.
    mutating func parseKeepingEveryBlock() -> GovernanceRead {
        guard let source = parseDocument() else {
            return GovernanceRead(source: nil, diagnostics: diagnostics)
        }
        return GovernanceRead(source: source, diagnostics: diagnostics)
    }

    mutating func parse() -> GovernanceRead {
        guard let source = parseDocument() else {
            return GovernanceRead(source: nil, diagnostics: diagnostics)
        }
        return GovernanceRead(
            source: diagnostics.contains { $0.severity == .error } ? nil : source,
            diagnostics: diagnostics
        )
    }

    private mutating func parseDocument() -> GovernanceSource? {
        guard expectKeyword("governance") else { return nil }
        guard expectKeyword("for") else { return nil }
        guard let name = expect(.string, "the system's name") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var threats: [SourceGovernedThreat] = []
        var actions: [SourcePlannedWork] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "stale":
                advance()
                if current.text == "action" {
                    if let action = parseWork(keyword: "action", isStale: true) {
                        actions.append(action)
                    }
                } else if let threat = parseThreat(isStale: true) {
                    threats.append(threat)
                }
            case "threat":
                if let threat = parseThreat(isStale: false) { threats.append(threat) }
            case "action":
                if let action = parseWork(keyword: "action", isStale: false) {
                    actions.append(action)
                }
            default:
                record(
                    "a governance file holds threat, action, stale threat and stale action, "
                        + "not \"\(current.text)\""
                )
                skipToNextBlock()
            }
        }
        _ = expect(.rightBrace, "}")

        var seen: Set<String> = []
        for threat in threats where seen.insert(threat.key.value).inserted == false {
            record("\(threat.key.value) is governed twice", at: tokens[0])
        }
        var seenActions: Set<String> = []
        for action in actions where seenActions.insert(action.label).inserted == false {
            record("\(action.label) is governed twice", at: tokens[0])
        }

        return GovernanceSource(systemName: name.text, threats: threats, actions: actions)
    }

    private mutating func parseThreat(isStale: Bool) -> SourceGovernedThreat? {
        guard expectKeyword("threat") else { return nil }
        guard let threatId = expect(.string, "the threat's identifier") else { return nil }

        guard current.kind == .identifier, current.text == "on" else {
            record("a threat says what raised it: on component, on zone or on flow")
            return nil
        }
        advance()

        let kindToken = current
        guard let kind = expect(.identifier, "component, zone or flow") else { return nil }
        if Self.sourceKinds.contains(kind.text) == false {
            record(
                "a threat is raised by a component, a zone or a flow, not \"\(kind.text)\"",
                at: kindToken
            )
        }
        guard let sourceId = expect(.string, "the identifier of what raised it") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var accepted: [SourceAcceptedRisk] = []
        var work: [SourcePlannedWork] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "stale":
                advance()
                if current.text == "accepted" {
                    if let risk = parseAccepted(isStale: true) { accepted.append(risk) }
                } else if let planned = parseWork(keyword: "work", isStale: true) {
                    work.append(planned)
                }
            case "accepted":
                if let risk = parseAccepted(isStale: false) { accepted.append(risk) }
            case "work":
                if let planned = parseWork(keyword: "work", isStale: false) { work.append(planned) }
            default:
                record(
                    "a governed threat holds accepted, work, stale accepted and stale work, "
                        + "not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceGovernedThreat(
            threatId: threatId.text,
            sourceKind: kind.text,
            sourceId: sourceId.text,
            accepted: accepted,
            work: work,
            isStale: isStale
        )
    }

    private mutating func parseAccepted(isStale: Bool) -> SourceAcceptedRisk? {
        guard expectKeyword("accepted") else { return nil }
        guard let control = expect(.string, "the control's description") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var owner = ""
        var acceptedOn: String?
        var reviewBy: String?
        var rationale = ""
        var sources: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "owner": owner = parseTextAttribute() ?? ""
            case "accepted_on": acceptedOn = parseDateAttribute(named: "accepted_on")
            case "review_by": reviewBy = parseDateAttribute(named: "review_by")
            case "rationale": rationale = parseTextAttribute() ?? ""
            case "sources": sources = parseListAttribute()
            default:
                record(
                    "an accepted risk holds owner, accepted_on, review_by, rationale and "
                        + "sources, not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceAcceptedRisk(
            control: control.text,
            owner: owner,
            acceptedOn: acceptedOn,
            reviewBy: reviewBy,
            rationale: rationale,
            sources: sources,
            isStale: isStale
        )
    }

    private mutating func parseWork(keyword: String, isStale: Bool) -> SourcePlannedWork? {
        guard expectKeyword(keyword) else { return nil }
        guard let label = expect(.string, "the label") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var owner = ""
        var effort: String?
        var dueBy: String?
        var status = SourcePlannedWork.defaultStatus
        var acceptance = ""
        var note = ""
        var sources: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "owner": owner = parseTextAttribute() ?? ""
            case "effort":
                let token = current
                effort = parseTextAttribute()
                if let raw = effort, SourcePlannedWork.efforts.contains(raw) == false {
                    record(
                        "effort is \"\(raw)\"; this application holds "
                            + SourcePlannedWork.efforts.map { "\"\($0)\"" }.joined(separator: ", "),
                        at: token
                    )
                    effort = nil
                }
            case "due_by": dueBy = parseDateAttribute(named: "due_by")
            case "status":
                let token = current
                let raw = parseTextAttribute() ?? SourcePlannedWork.defaultStatus
                if SourcePlannedWork.statuses.contains(raw) {
                    status = raw
                } else {
                    record(
                        "status is \"\(raw)\"; this application holds "
                            + SourcePlannedWork.statuses.map { "\"\($0)\"" }.joined(separator: ", "),
                        at: token
                    )
                }
            case "acceptance": acceptance = parseTextAttribute() ?? ""
            case "note": note = parseTextAttribute() ?? ""
            case "sources": sources = parseListAttribute()
            default:
                record(
                    "planned work holds owner, effort, due_by, status, acceptance, note and "
                        + "sources, not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourcePlannedWork(
            label: label.text,
            owner: owner,
            effort: effort,
            dueBy: dueBy,
            status: status,
            acceptance: acceptance,
            note: note,
            sources: sources,
            isStale: isStale
        )
    }

    /// A date the file states, or nil when the text is not one. The two
    /// messages say which of the two faults it is.
    private mutating func parseDateAttribute(named attribute: String) -> String? {
        let token = current
        guard let raw = parseTextAttribute() else { return nil }
        switch GovernanceDate.read(raw) {
        case .success(let date):
            return date.description
        case .failure(let fault):
            record(fault.message(attribute: attribute, raw: raw), at: token)
            return nil
        }
    }

    // MARK: the tokens

    private var current: Token { tokens[min(index, tokens.count - 1)] }

    private mutating func advance() {
        if index < tokens.count - 1 { index += 1 }
    }

    private mutating func expectKeyword(_ keyword: String) -> Bool {
        guard current.kind == .identifier, current.text == keyword else {
            record("expected \(keyword), not \"\(current.text)\"")
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
            Diagnostic(severity: severity, line: where_.line, column: where_.column, message: message)
        )
    }

    private mutating func parseTextAttribute() -> String? {
        advance()
        guard expect(.equals, "=") != nil else { return nil }
        return expect(.string, "a text in quotation marks")?.text
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
            advance()
        } else if current.kind == .leftBrace {
            skipToNextBlock()
        }
    }
}
