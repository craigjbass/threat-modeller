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
        var mitigations: [SourceLibraryMitigation] = []
        var threatActors: [SourceThreatActor] = []
        var categories: [SourceTaxonomyEntry] = []
        var severities: [SourceTaxonomyEntry] = []
        var strides: [SourceTaxonomyEntry] = []
        var overrides: [SourceLibraryOverride] = []
        var classifications: [SourceClassification] = []

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
            case "mitigation":
                if let mitigation = parseMitigation() { mitigations.append(mitigation) }
            case "category":
                if let entry = parseTaxonomyEntry("the category's identifier") {
                    categories.append(entry)
                }
            case "severity":
                if let entry = parseTaxonomyEntry("the severity's identifier") {
                    severities.append(entry)
                }
            case "stride":
                if let entry = parseTaxonomyEntry("the stride category's identifier") {
                    strides.append(entry)
                }
            case "classification":
                if let level = parseClassification() { classifications.append(level) }
            case "override":
                if let override = parseOverride() { overrides.append(override) }
            case "threat_actor":
                let token = current
                if let actor = parseThreatActor() {
                    if threatActors.contains(where: { $0.id == actor.id }) {
                        record("the threat actor \"\(actor.id)\" is declared twice", at: token)
                    } else {
                        threatActors.append(actor)
                    }
                }
            default:
                record(
                    "a library holds name, catalogue, technology, threat, mitigation, "
                        + "threat_actor, category, severity, stride, override and "
                        + "classification, not "
                        + "\"\(current.text)\""
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
            threats: threats,
            mitigations: mitigations,
            threatActors: threatActors,
            categories: categories,
            severities: severities,
            strides: strides,
            overrides: overrides,
            classifications: classifications
        )
    }

    /// One level of a classification scheme. The order the file states is the
    /// scheme: the first is the least sensitive.
    private mutating func parseClassification() -> SourceClassification? {
        advance()
        guard let id = expect(.string, "the level's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var label: String?
        var colour: String?
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": label = parseTextAttribute()
            case "colour": colour = parseTextAttribute()
            default:
                record("a classification holds name and colour, not \"\(current.text)\"")
                skipToNextBlock()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceClassification(id: id.text, label: label ?? id.text, colour: colour)
    }

    /// What this library changes about a threat the catalogue already holds.
    private mutating func parseOverride() -> SourceLibraryOverride? {
        advance()
        guard let id = expect(.string, "the threat's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var severityLabel: String?
        var likelihood: String?
        var description: String?
        var controls: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "severity": severityLabel = parseTextAttribute()
            case "description": description = parseTextAttribute()
            case "likelihood":
                let token = current
                likelihood = parseTextAttribute()
                if let word = likelihood, Likelihood(rawValue: word) == nil {
                    record(
                        "likelihood is \"\(word)\"; this application holds \"commodity\", "
                            + "\"targeted\", \"research\"",
                        at: token
                    )
                    likelihood = nil
                }
            case "control":
                advance()
                if let text = expect(.string, "the control's description") {
                    controls.append(text.text)
                }
            default:
                record(
                    "an override holds severity, likelihood, description and control, not "
                        + "\"\(current.text)\""
                )
                skipToNextBlock()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceLibraryOverride(
            threatId: id.text,
            severityLabel: severityLabel,
            likelihood: likelihood,
            description: description,
            controlDescriptions: controls
        )
    }

    /// One word a library adds to the taxonomy. Every one reads the same:
    /// an identifier and a name.
    private mutating func parseTaxonomyEntry(_ what: String) -> SourceTaxonomyEntry? {
        advance()
        guard let id = expect(.string, what) else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var label: String?
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": label = parseTextAttribute()
            default:
                record("this block holds name, not \"\(current.text)\"")
                skipToNextBlock()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceTaxonomyEntry(id: id.text, label: label ?? id.text)
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
        var controls: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "category": category = parseTextAttribute()
            case "description": description = parseTextAttribute() ?? ""
            case "threats": threatIds = parseListAttribute()
            case "encrypts": encrypts = parseBooleanAttribute() ?? false
            case "control":
                advance()
                if let text = expect(.string, "the control's description") {
                    controls.append(text.text)
                }
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
            encrypts: encrypts,
            controlDescriptions: controls
        )
    }

    private mutating func parseThreat() -> SourceLibraryThreat? {
        advance()
        guard let id = expect(.string, "the threat's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var description = ""
        var severityLabel: String?
        var strideIds: [String] = []
        var impacts: [String] = []
        var isConnectionThreat = false
        var isZoneThreat = false
        var zoneContext: String?
        var mitre: [SourceMitreTechnique] = []
        var controls: [String] = []
        var appliesTo: [String] = []
        var boundary: String?
        var runsAs: [String] = []
        var isPathwayThreat = false
        var likelihood: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "description": description = parseTextAttribute() ?? ""
            case "severity": severityLabel = parseTextAttribute()
            case "stride": strideIds = parseListAttribute()
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
            case "connection": isConnectionThreat = parseBooleanAttribute() ?? false
            case "zone": isZoneThreat = parseBooleanAttribute() ?? false
            case "zone_context": zoneContext = parseTextAttribute()
            case "mitre":
                if let technique = parseMitre() { mitre.append(technique) }
            case "control":
                if let control = parseControl() { controls.append(control) }
            case "applies_to": appliesTo = parseListAttribute()
            case "boundary": boundary = parseTextAttribute()
            case "runs_as": runsAs = parseListAttribute()
            case "pathway": isPathwayThreat = parseBooleanAttribute() ?? false
            case "likelihood":
                let token = current
                if peekIsNumber() {
                    let prior = parseNumberAttribute()
                    if let prior {
                        if Likelihood(prior: prior) != nil {
                            likelihood = String(prior)
                        } else {
                            record("likelihood is \(prior); a whole number runs from 0 to 100", at: token)
                        }
                    }
                } else {
                    let raw = parseTextAttribute() ?? ""
                    if Likelihood(rawValue: raw) == nil {
                        record(
                            "likelihood is \"\(raw)\"; this application holds "
                                + Likelihood.allTiers.map { "\"\($0.id)\"" }.joined(separator: ", ")
                                + ", or a whole number from 0 to 100",
                            at: token
                        )
                    } else {
                        likelihood = raw
                    }
                }
            default:
                record(
                    "a threat holds name, description, severity, stride, impacts, "
                        + "connection, zone, zone_context, mitre, control, applies_to, "
                        + "boundary, runs_as, pathway and likelihood, not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let name else {
            record("the threat \"\(id.text)\" has no name", at: id)
            return nil
        }
        guard let severityLabel else {
            record("the threat \"\(id.text)\" has no severity", at: id)
            return nil
        }
        return SourceLibraryThreat(
            id: id.text,
            name: name,
            description: description,
            severityLabel: severityLabel,
            strideIds: strideIds,
            impacts: impacts,
            isConnectionThreat: isConnectionThreat,
            isZoneThreat: isZoneThreat,
            zoneContext: zoneContext,
            mitre: mitre,
            controlDescriptions: controls,
            appliesTo: appliesTo,
            boundary: boundary,
            runsAs: runsAs,
            isPathwayThreat: isPathwayThreat,
            likelihood: likelihood
        )
    }

    private mutating func parseMitigation() -> SourceLibraryMitigation? {
        advance()
        guard let id = expect(.string, "the mitigation's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var description = ""
        var mitigates: [String] = []
        var providedBy: [String] = []
        var reducesRiskBy: Int?
        var mode: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "description": description = parseTextAttribute() ?? ""
            case "mitigates": mitigates = parseListAttribute()
            case "provided_by": providedBy = parseListAttribute()
            case "reduces_risk_by":
                let token = current
                reducesRiskBy = parseNumberAttribute()
                if let percent = reducesRiskBy, percent < 0 || percent > 100 {
                    record("reduces_risk_by is \(percent); it runs from 0 to 100", at: token)
                }
            case "mode":
                let token = current
                mode = parseTextAttribute()
                if let word = mode, PathwayMitigationMode(rawValue: word) == nil {
                    record(
                        "mode is \"\(word)\"; this application holds \"remove\" and \"reduce\"",
                        at: token
                    )
                    mode = nil
                }
            default:
                record(
                    "a mitigation holds name, description, mitigates, provided_by, "
                        + "reduces_risk_by and mode, not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let name else {
            record("the mitigation \"\(id.text)\" has no name", at: id)
            return nil
        }
        guard mitigates.isEmpty == false else {
            record("the mitigation \"\(id.text)\" names no threats", at: id)
            return nil
        }
        guard providedBy.isEmpty == false else {
            record("the mitigation \"\(id.text)\" names no technologies", at: id)
            return nil
        }
        return SourceLibraryMitigation(
            id: id.text,
            name: name,
            description: description,
            mitigatesThreatIds: mitigates,
            technologyIds: providedBy,
            reducesRiskBy: reducesRiskBy ?? 0,
            mode: mode
        )
    }

    /// A `threat_actor` block. The same attributes in a `.lib` file and in an
    /// `.arch` file, so an actor reads the same in both.
    private mutating func parseThreatActor() -> SourceThreatActor? {
        advance()
        guard let id = expect(.string, "the threat actor's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var description = ""
        var aliases: [String] = []
        var capability: String?
        var intent = ""
        var performs: [String] = []
        var techniques: [String] = []
        var performsCatalogueTier: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "description": description = parseTextAttribute() ?? ""
            case "aliases": aliases = parseListAttribute()
            case "capability":
                let token = current
                capability = parseTextAttribute()
                if let word = capability, Likelihood(rawValue: word) == nil {
                    record(
                        "capability is \"\(word)\"; this application holds \"commodity\", "
                            + "\"targeted\", \"research\"",
                        at: token
                    )
                    capability = nil
                }
            case "intent": intent = parseTextAttribute() ?? ""
            case "performs": performs = parseListAttribute()
            case "techniques": techniques = parseListAttribute()
            case "performs_catalogue_tier":
                let token = current
                performsCatalogueTier = parseTextAttribute()
                if let word = performsCatalogueTier, Likelihood(rawValue: word) == nil {
                    record(
                        "performs_catalogue_tier is \"\(word)\"; this application holds "
                            + "\"commodity\", \"targeted\", \"research\"",
                        at: token
                    )
                    performsCatalogueTier = nil
                }
            default:
                record(
                    "a threat actor holds name, description, aliases, capability, intent, "
                        + "performs, techniques and performs_catalogue_tier, not \"\(current.text)\""
                )
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let name else {
            record("the threat actor \"\(id.text)\" has no name", at: id)
            return nil
        }
        return SourceThreatActor(
            id: id.text,
            name: name,
            description: description,
            aliases: aliases,
            capability: capability,
            intent: intent,
            performs: performs,
            techniques: techniques,
            performsCatalogueTier: performsCatalogueTier
        )
    }

    private mutating func parseMitre() -> SourceMitreTechnique? {
        advance()
        guard let id = expect(.string, "the technique's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var tactic: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "tactic": tactic = parseTextAttribute()
            default:
                record("a mitre technique holds name and tactic, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let name else {
            record("the technique \"\(id.text)\" has no name", at: id)
            return nil
        }
        guard let tactic else {
            record("the technique \"\(id.text)\" has no tactic", at: id)
            return nil
        }
        return SourceMitreTechnique(id: id.text, name: name, tactic: tactic)
    }

    /// A control is a statement, not a block: a library says what a control is
    /// and a controls file says its status.
    private mutating func parseControl() -> String? {
        advance()
        return expect(.string, "the control's description")?.text
    }

    // MARK: what the file must hold once it parses

    /// Each fault names the first line, because it is a fault of the file
    /// rather than of one token.
    private mutating func check(_ source: LibrarySource) {
        var technologyIds: Set<String> = []
        for technology in source.technologies
        where technologyIds.insert(technology.id).inserted == false {
            record("the technology \"\(technology.id)\" is declared twice", at: tokens[0])
        }

        var threatIds: Set<String> = []
        for threat in source.threats where threatIds.insert(threat.id).inserted == false {
            record("the threat \"\(threat.id)\" is declared twice", at: tokens[0])
        }

        // A threat with no control is a threat nobody can answer, so `check`
        // would report it as unanswered for ever.
        for threat in source.threats where threat.controlDescriptions.isEmpty {
            record(
                "the threat \"\(threat.id)\" offers no control, so nothing can answer it",
                at: tokens[0],
                severity: .warning
            )
        }

        // A threat nothing names and nothing raises is a threat this library
        // states for no reader.
        let named = Set(source.technologies.flatMap(\.threatIds))
        for threat in source.threats
        where named.contains(threat.id) == false
            && threat.isZoneThreat == false
            && threat.isConnectionThreat == false {
            record(
                "no technology in this library names \"\(threat.id)\", so nothing raises it",
                at: tokens[0],
                severity: .warning
            )
        }
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

    private mutating func parseNumberAttribute() -> Int? {
        advance()
        guard expect(.equals, "=") != nil else { return nil }
        guard let token = expect(.number, "a whole number") else { return nil }
        return Int(token.text)
    }

    /// True when the value after `name =` is a number rather than a text.
    private func peekIsNumber() -> Bool {
        tokens[min(index + 2, tokens.count - 1)].kind == .number
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
