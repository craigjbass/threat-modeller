import ThreatModelKit

/// Turns tokens into a `ControlsSource`.
///
/// Like the architecture parser it never throws and never stops at the first
/// fault.
struct ControlsParser {
    private let tokens: [Token]
    private var index = 0
    private var diagnostics: [Diagnostic]

    init(tokens: [Token], faults: [Diagnostic]) {
        self.tokens = tokens
        diagnostics = faults
    }

    private static let sourceKinds: Set<String> = ["component", "zone", "flow"]

    mutating func parse() -> ControlsRead {
        guard let source = parseDocument() else {
            return ControlsRead(source: nil, diagnostics: diagnostics)
        }
        return ControlsRead(
            source: diagnostics.contains { $0.severity == .error } ? nil : source,
            diagnostics: diagnostics
        )
    }

    private mutating func parseDocument() -> ControlsSource? {
        guard expectKeyword("controls") else { return nil }
        guard expectKeyword("for") else { return nil }
        guard let name = expect(.string, "the system's name") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var catalogueTag: String?
        var answers: [SourceThreatAnswer] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "catalogue":
                catalogueTag = parseTextAttribute()
            case "stale":
                advance()
                if let answer = parseThreat(isStale: true) { answers.append(answer) }
            case "threat":
                if let answer = parseThreat(isStale: false) { answers.append(answer) }
            default:
                record("a controls file holds catalogue, threat and stale threat, not \"\(current.text)\"")
                skipToNextBlock()
            }
        }
        _ = expect(.rightBrace, "}")

        var seen: Set<String> = []
        for answer in answers where seen.insert(answer.key.value).inserted == false {
            record("\(answer.key.value) is answered twice", at: tokens[0])
        }

        return ControlsSource(systemName: name.text, catalogueTag: catalogueTag, answers: answers)
    }

    private mutating func parseThreat(isStale: Bool) -> SourceThreatAnswer? {
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

        var severityLabel: String?
        var score: Int?
        var likelihood: LikelihoodFinding?
        var controls: [SourceControlAnswer] = []
        var compensating: [CompensatingControl] = []
        var recommendations: [SourceRecommendation] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "severity": severityLabel = parseTextAttribute()
            case "score": score = parseNumberAttribute()
            case "likelihood":
                let token = current
                if let finding = parseLikelihood() {
                    if likelihood != nil {
                        record("this threat holds two likelihood blocks; it holds one", at: token)
                    } else {
                        likelihood = finding
                    }
                }
            case "control":
                if let control = parseControl() { controls.append(control) }
            case "compensating":
                if let control = parseCompensating() { compensating.append(control) }
            case "recommendation":
                if let recommendation = parseRecommendation() { recommendations.append(recommendation) }
            default:
                record(
                    "a threat holds severity, score, likelihood, control, compensating and "
                        + "recommendation, not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceThreatAnswer(
            threatId: threatId.text,
            sourceKind: kind.text,
            sourceId: sourceId.text,
            severityLabel: severityLabel,
            score: score,
            likelihood: likelihood,
            controls: controls,
            compensating: compensating,
            recommendations: recommendations,
            isStale: isStale
        )
    }

    private mutating func parseLikelihood() -> LikelihoodFinding? {
        advance()
        guard let label = expect(.string, "what the finding is called") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var tier: String?
        var prior: Int?
        var rationale: String?
        var sources: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "tier":
                let token = current
                let raw = parseTextAttribute() ?? ""
                if Likelihood(rawValue: raw) == nil {
                    record(
                        "tier is \"\(raw)\"; this application holds "
                            + Likelihood.allTiers.map { "\"\($0.id)\"" }.joined(separator: ", "),
                        at: token
                    )
                } else {
                    tier = raw
                }
            case "prior":
                let token = current
                prior = parseNumberAttribute()
                if let value = prior, Likelihood(prior: value) == nil {
                    record("prior is \(value); it runs from 0 to 100", at: token)
                }
            case "rationale":
                rationale = parseTextAttribute()
            case "sources":
                sources = parseListAttribute()
            default:
                record("a likelihood holds tier, prior, rationale and sources, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        if tier != nil && prior != nil {
            record("the likelihood \"\(label.text)\" states a tier and a prior; it states one", at: label)
            return nil
        }
        guard let rationale, rationale.isEmpty == false else {
            // Evidence nobody can justify is not evidence.
            record("the likelihood \"\(label.text)\" has no rationale", at: label)
            return nil
        }
        let read = tier.flatMap(Likelihood.init(rawValue:)) ?? prior.flatMap(Likelihood.init(prior:))
        guard let read else {
            record("the likelihood \"\(label.text)\" states no tier and no prior", at: label)
            return nil
        }
        return LikelihoodFinding(
            label: label.text,
            likelihood: read,
            rationale: rationale,
            sources: sources
        )
    }

    private mutating func parseControl() -> SourceControlAnswer? {
        advance()
        guard let description = expect(.string, "the control's description") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var status = ControlStatus.notImplemented
        var note: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "status":
                let token = current
                let raw = parseTextAttribute() ?? ""
                if let read = ControlStatus(rawValue: raw) {
                    status = read
                } else {
                    record(
                        "status is \"\(raw)\"; this application holds "
                            + ControlStatus.allCases.map { "\"\($0.rawValue)\"" }
                                .sorted().joined(separator: ", "),
                        at: token
                    )
                }
            case "note":
                note = parseTextAttribute()
            default:
                record("a control holds status and note, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceControlAnswer(description: description.text, status: status, note: note)
    }

    private mutating func parseCompensating() -> CompensatingControl? {
        advance()
        guard let label = expect(.string, "what the compensating control is called") else {
            return nil
        }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var percent: Int?
        var rationale: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "reduces_risk_by":
                let token = current
                percent = parseNumberAttribute()
                if let value = percent, value < 0 || value > 100 {
                    record("reduces_risk_by is \(value); it runs from 0 to 100", at: token)
                }
            case "rationale":
                rationale = parseTextAttribute()
            default:
                record("a compensating control holds reduces_risk_by and rationale, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let rationale, rationale.isEmpty == false else {
            // A reduction nobody can justify is not one.
            record("the compensating control \"\(label.text)\" has no rationale", at: label)
            return nil
        }
        return CompensatingControl(
            label: label.text,
            reducesRiskBy: percent ?? 0,
            rationale: rationale
        )
    }

    private mutating func parseRecommendation() -> SourceRecommendation? {
        advance()
        guard let text = expect(.string, "what the recommendation says") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var note: String?
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "note": note = parseTextAttribute()
            default:
                record("a recommendation holds note, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")
        return SourceRecommendation(text: text.text, note: note)
    }

    // MARK: the attributes

    private mutating func parseTextAttribute() -> String? {
        advance()
        guard expect(.equals, "=") != nil else { return nil }
        return expect(.string, "a text in quotation marks")?.text
    }

    private mutating func parseNumberAttribute() -> Int? {
        advance()
        guard expect(.equals, "=") != nil else { return nil }
        guard let token = expect(.number, "a whole number") else { return nil }
        return Int(token.text)
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
