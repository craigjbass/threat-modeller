import ThreatModelKit

/// Turns tokens into a `PolicySource`.
///
/// The rules are a fixed set of names, so a name outside the set is an error
/// with the whole set beside it: a rule a team cannot mistype.
struct PolicyParser {
    private let tokens: [Token]
    private var index = 0
    private var diagnostics: [Diagnostic]

    init(tokens: [Token], faults: [Diagnostic]) {
        self.tokens = tokens
        diagnostics = faults
    }

    mutating func parse() -> PolicyRead {
        guard let source = parseDocument() else {
            return PolicyRead(source: nil, diagnostics: diagnostics)
        }
        return PolicyRead(
            source: diagnostics.contains { $0.severity == .error } ? nil : source,
            diagnostics: diagnostics
        )
    }

    private mutating func parseDocument() -> PolicySource? {
        guard expectKeyword("policy") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var maxOpenAtLevel: RiskLevel?
        var acceptedRequiresOwner = false
        var acceptedRequiresReviewBy = false
        var implementedRequiresEvidenceAbove: RiskLevel?
        var restrictedDataStaysOutOfPublicZones = false
        var assumptionsRequireOwner = false
        var systemRequiresOwner = false

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "max_open_at_level":
                maxOpenAtLevel = parseLevelAttribute(named: "max_open_at_level")
            case "implemented_requires_evidence_above":
                implementedRequiresEvidenceAbove = parseLevelAttribute(
                    named: "implemented_requires_evidence_above"
                )
            case "accepted_requires_owner":
                acceptedRequiresOwner = parseBooleanAttribute() ?? false
            case "accepted_requires_review_by":
                acceptedRequiresReviewBy = parseBooleanAttribute() ?? false
            case "restricted_data_stays_out_of_public_zones":
                restrictedDataStaysOutOfPublicZones = parseBooleanAttribute() ?? false
            case "assumptions_require_owner":
                assumptionsRequireOwner = parseBooleanAttribute() ?? false
            case "system_requires_owner":
                systemRequiresOwner = parseBooleanAttribute() ?? false
            default:
                record(
                    "a policy holds "
                        + PolicySource.ruleNames.joined(separator: ", ")
                        + ", not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return PolicySource(
            maxOpenAtLevel: maxOpenAtLevel,
            acceptedRequiresOwner: acceptedRequiresOwner,
            acceptedRequiresReviewBy: acceptedRequiresReviewBy,
            implementedRequiresEvidenceAbove: implementedRequiresEvidenceAbove,
            restrictedDataStaysOutOfPublicZones: restrictedDataStaysOutOfPublicZones,
            assumptionsRequireOwner: assumptionsRequireOwner,
            systemRequiresOwner: systemRequiresOwner
        )
    }

    private mutating func parseLevelAttribute(named rule: String) -> RiskLevel? {
        let token = current
        guard let raw = parseTextAttribute() else { return nil }
        guard let level = RiskLevel(rawValue: raw) else {
            record(
                "\(rule) is \"\(raw)\"; this application holds "
                    + RiskLevel.allCases.map { "\"\($0.rawValue)\"" }.joined(separator: ", "),
                at: token
            )
            return nil
        }
        return level
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

    private mutating func parseBooleanAttribute() -> Bool? {
        advance()
        guard expect(.equals, "=") != nil else { return nil }
        return expect(.boolean, "true or false")?.text == "true"
    }

    private mutating func skipAttribute() {
        advance()
        if current.kind == .equals {
            advance()
            advance()
        }
    }
}
