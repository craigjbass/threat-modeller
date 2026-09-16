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
        var riskTolerance: String?
        var answers: [SourceThreatAnswer] = []
        var trees: [SourceTreeAnswer] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "catalogue":
                catalogueTag = parseTextAttribute()
            case "tolerance":
                let token = current
                let raw = parseTextAttribute() ?? ""
                if RiskLevel(rawValue: raw) == nil {
                    record(
                        "tolerance is \"\(raw)\"; this application holds "
                            + RiskLevel.allCases.map { "\"\($0.rawValue)\"" }.joined(separator: ", "),
                        at: token
                    )
                } else {
                    riskTolerance = raw
                }
            case "stale":
                advance()
                if current.text == "tree" {
                    if let tree = parseTree(isStale: true) { trees.append(tree) }
                } else if let answer = parseThreat(isStale: true) {
                    answers.append(answer)
                }
            case "threat":
                if let answer = parseThreat(isStale: false) { answers.append(answer) }
            case "tree":
                if let tree = parseTree(isStale: false) { trees.append(tree) }
            default:
                record(
                    "a controls file holds catalogue, tolerance, threat, tree, stale threat "
                        + "and stale tree, not \"\(current.text)\""
                )
                skipToNextBlock()
            }
        }
        _ = expect(.rightBrace, "}")

        var seen: Set<String> = []
        for answer in answers where seen.insert(answer.key.value).inserted == false {
            record("\(answer.key.value) is answered twice", at: tokens[0])
        }

        return ControlsSource(
            systemName: name.text,
            catalogueTag: catalogueTag,
            riskTolerance: riskTolerance,
            answers: answers,
            trees: trees
        )
    }

    /// A `tree` stanza, which the compiler writes and a person reads.
    private mutating func parseTree(isStale: Bool) -> SourceTreeAnswer? {
        guard expectKeyword("tree") else { return nil }
        guard let id = expect(.string, "the tree's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var goalKey = ""
        var chain = 0
        var raisesRiskBy = 0
        var score = 0
        var scoreBefore = 0
        var steps: [SourceTreeStepAnswer] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "goal": goalKey = parseTextAttribute() ?? ""
            case "chain": chain = parseNumberAttribute() ?? 0
            case "raises_risk_by": raisesRiskBy = parseNumberAttribute() ?? 0
            case "score": score = parseNumberAttribute() ?? 0
            case "score_before": scoreBefore = parseNumberAttribute() ?? 0
            case "step":
                if let step = parseTreeStep() { steps.append(step) }
            default:
                record(
                    "a tree holds goal, chain, raises_risk_by, score, score_before and step, "
                        + "not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceTreeAnswer(
            treeId: id.text,
            goalKey: goalKey,
            chain: chain,
            raisesRiskBy: raisesRiskBy,
            score: score,
            scoreBefore: scoreBefore,
            steps: steps,
            isStale: isStale
        )
    }

    private mutating func parseTreeStep() -> SourceTreeStepAnswer? {
        advance()
        guard let key = expect(.string, "the step's threat key") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var state = "open"
        var closedBy: String?
        var position: Int?
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "state": state = parseTextAttribute() ?? "open"
            case "by": closedBy = parseTextAttribute()
            case "position": position = parseNumberAttribute()
            default:
                record("a step holds state, by and position, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")
        return SourceTreeStepAnswer(key: key.text, state: state, closedBy: closedBy, position: position)
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
        var severityDecision: SeverityDecision?
        var controls: [SourceControlAnswer] = []
        var compensating: [CompensatingControl] = []
        var recommendations: [SourceRecommendation] = []
        var impacts: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "severity": severityLabel = parseTextAttribute()
            case "score": score = parseNumberAttribute()
            case "impacts":
                let token = current
                impacts = parseListAttribute().filter { word in
                    guard ThreatImpact(rawValue: word) == nil else { return true }
                    record(
                        "impacts holds \"\(word)\"; this application holds "
                            + ThreatImpact.allCases.map { "\"\($0.rawValue)\"" }
                                .joined(separator: ", "),
                        at: token
                    )
                    return false
                }
            case "likelihood":
                let token = current
                if let finding = parseLikelihood() {
                    if likelihood != nil {
                        record("this threat holds two likelihood blocks; it holds one", at: token)
                    } else {
                        likelihood = finding
                    }
                }
            case "severity_override":
                let token = current
                if let decision = parseSeverityOverride() {
                    if severityDecision != nil {
                        record("this threat holds two severity_override blocks; it holds one", at: token)
                    } else {
                        severityDecision = decision
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
                    "a threat holds severity, score, impacts, likelihood, severity_override, "
                        + "control, compensating and recommendation, not \"\(current.text)\""
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
            severityDecision: severityDecision,
            impacts: impacts,
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
        var sawTier = false
        var sawPrior = false
        var rationale: String?
        var sources: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "tier":
                sawTier = true
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
                sawPrior = true
                let token = current
                let value = parseNumberAttribute()
                if let value {
                    if Likelihood(prior: value) == nil {
                        record("prior is \(value); it runs from 0 to 100", at: token)
                    } else {
                        prior = value
                    }
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
            // A rejected tier or prior already carries its own fault above; say
            // "states no tier and no prior" only when neither was named at all.
            if sawTier == false && sawPrior == false {
                record("the likelihood \"\(label.text)\" states no tier and no prior", at: label)
            }
            return nil
        }
        return LikelihoodFinding(
            label: label.text,
            likelihood: read,
            rationale: rationale,
            sources: sources
        )
    }

    private mutating func parseSeverityOverride() -> SeverityDecision? {
        advance()
        guard let label = expect(.string, "the severity the assessor chose") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var rationale: String?
        var sources: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "rationale": rationale = parseTextAttribute()
            case "sources": sources = parseListAttribute()
            default:
                record("a severity_override holds rationale and sources, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let rationale, rationale.isEmpty == false else {
            // A severity decision nobody can justify is not one.
            record("the severity_override \"\(label.text)\" has no rationale", at: label)
            return nil
        }
        return SeverityDecision(severityId: label.text, rationale: rationale, sources: sources)
    }

    private mutating func parseControl() -> SourceControlAnswer? {
        advance()
        guard let description = expect(.string, "the control's description") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var status = ControlStatus.notImplemented
        var note: String?
        var evidence: ControlEvidence?
        var reference = ""
        var verifiedOn: GovernanceDate?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "evidence": evidence = parseEvidenceAttribute()
            case "reference": reference = parseTextAttribute() ?? ""
            case "verified_on": verifiedOn = parseVerifiedOnAttribute()
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
                record(
                    "a control holds status, note, evidence, reference and verified_on, "
                        + "not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceControlAnswer(
            description: description.text,
            status: status,
            note: note,
            proof: ControlProof(
                evidence: evidence,
                reference: reference,
                verifiedOn: verifiedOn
            )
        )
    }

    private mutating func parseCompensating() -> CompensatingControl? {
        advance()
        guard let label = expect(.string, "what the compensating control is called") else {
            return nil
        }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var percent: Int?
        var rationale: String?
        var sources: [String] = []
        var evidence: ControlEvidence?
        var reference = ""
        var verifiedOn: GovernanceDate?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "evidence": evidence = parseEvidenceAttribute()
            case "reference": reference = parseTextAttribute() ?? ""
            case "verified_on": verifiedOn = parseVerifiedOnAttribute()
            case "reduces_risk_by":
                let token = current
                percent = parseNumberAttribute()
                if let value = percent, value < 0 || value > 100 {
                    record("reduces_risk_by is \(value); it runs from 0 to 100", at: token)
                }
            case "rationale":
                rationale = parseTextAttribute()
            case "sources":
                sources = parseListAttribute()
            default:
                record(
                    "a compensating control holds reduces_risk_by, rationale, sources, "
                        + "evidence, reference and verified_on, not \"\(current.text)\""
                )
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
            rationale: rationale,
            sources: sources,
            proof: ControlProof(
                evidence: evidence,
                reference: reference,
                verifiedOn: verifiedOn
            )
        )
    }

    /// The tier a control states, or nil when the word is no tier.
    private mutating func parseEvidenceAttribute() -> ControlEvidence? {
        let token = current
        guard let raw = parseTextAttribute() else { return nil }
        guard let tier = ControlEvidence(rawValue: raw) else {
            record(
                "evidence is \"\(raw)\"; this application holds \(ControlEvidence.wordsItHolds)",
                at: token
            )
            return nil
        }
        return tier
    }

    /// The date somebody last checked, or nil when the text is not a date.
    private mutating func parseVerifiedOnAttribute() -> GovernanceDate? {
        let token = current
        guard let raw = parseTextAttribute() else { return nil }
        switch GovernanceDate.read(raw) {
        case .success(let date):
            return date
        case .failure(let fault):
            record(fault.message(attribute: "verified_on", raw: raw), at: token)
            return nil
        }
    }

    private mutating func parseRecommendation() -> SourceRecommendation? {
        advance()
        guard let text = expect(.string, "what the recommendation says") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var note: String?
        var sources: [String] = []
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "note": note = parseTextAttribute()
            case "sources": sources = parseListAttribute()
            default:
                record("a recommendation holds note and sources, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")
        return SourceRecommendation(text: text.text, note: note, sources: sources)
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
