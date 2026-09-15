import ThreatModelKit

/// Turns tokens into an `ArchitectureSource`.
///
/// It never throws and never stops at the first fault. On a token it did not
/// expect it records one diagnostic and skips to the next block boundary, so a
/// file with four faults reports four.
struct ArchitectureParser {
    private let tokens: [Token]
    private var index = 0
    private var diagnostics: [Diagnostic]

    init(tokens: [Token], faults: [Diagnostic]) {
        self.tokens = tokens
        diagnostics = faults
    }

    private static let zoneKinds: Set<String> = ["public", "private"]
    private static let networks: Set<String> = [
        "generic", "vpc", "subnet", "on-premises", "dmz", "management", "data"
    ]
    private static let flowKinds: Set<String> = ["network", "ipc", "file", "syscall", "human"]
    private static let boundaries: Set<String> = ["network", "privilege"]
    private static let privilegeLevels: Set<String> = ["user", "admin", "root", "system", "kernel"]
    private static let diagramShapes: Set<String> = ["actor", "process", "store"]

    mutating func parse() -> ArchitectureRead {
        guard let system = parseSystem() else {
            return ArchitectureRead(source: nil, diagnostics: diagnostics)
        }
        check(system)
        return ArchitectureRead(
            source: diagnostics.contains { $0.severity == .error } ? nil : system,
            diagnostics: diagnostics
        )
    }

    // MARK: the blocks

    private mutating func parseSystem() -> ArchitectureSource? {
        guard expectKeyword("system") else { return nil }
        guard let name = expect(.string, "the system's name") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var catalogueTag: String?
        var technologies: [SourceTechnology] = []
        var zones: [SourceZone] = []
        var components: [SourceComponent] = []
        var flows: [SourceFlow] = []
        var mitigates: [SourceMitigates] = []
        var riskTolerance: String?
        var assumptions: [SourceAssumption] = []
        var faces: [String] = []
        var requiresEvidenceAbove: String?
        var owner: String?
        var threatActors: [SourceThreatActor] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "catalogue":
                catalogueTag = parseTextAttribute()
            case "technology":
                if let technology = parseTechnology() { technologies.append(technology) }
            case "zone":
                if let zone = parseZone() { zones.append(zone) }
            case "component":
                if let component = parseComponent() { components.append(component) }
            case "flow":
                if let flow = parseFlow() { flows.append(flow) }
            case "mitigates":
                if let edge = parseMitigates() { mitigates.append(edge) }
            case "risk_tolerance":
                let token = current
                let raw = parseTextAttribute() ?? ""
                if RiskLevel(rawValue: raw) == nil {
                    record(
                        "risk_tolerance is \"\(raw)\"; this application holds "
                            + RiskLevel.allCases.map { "\"\($0.rawValue)\"" }.joined(separator: ", "),
                        at: token
                    )
                } else {
                    riskTolerance = raw
                }
            case "assumption":
                if let assumption = parseAssumption() { assumptions.append(assumption) }
            case "owner":
                owner = parseTextAttribute()
            case "requires_evidence_above":
                let token = current
                let raw = parseTextAttribute() ?? ""
                if RiskLevel(rawValue: raw) == nil {
                    record(
                        "requires_evidence_above is \"\(raw)\"; this application holds "
                            + RiskLevel.allCases.map { "\"\($0.rawValue)\"" }.joined(separator: ", "),
                        at: token
                    )
                } else {
                    requiresEvidenceAbove = raw
                }
            case "faces":
                // A second `faces` keeps the last value, the way every
                // repeated attribute does.
                faces = parseListAttribute()
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
                record("a system holds catalogue, owner, technology, zone, component, flow, mitigates, risk_tolerance, requires_evidence_above, assumption, faces and threat_actor, not \"\(current.text)\"")
                skipToNextBlock()
            }
        }
        _ = expect(.rightBrace, "}")

        let checked = checkedActions(on: mitigates, assumptions: assumptions)

        return ArchitectureSource(
            systemName: name.text,
            catalogueTag: catalogueTag,
            technologies: technologies,
            zones: zones,
            components: components,
            flows: flows,
            mitigates: checked,
            riskTolerance: riskTolerance,
            assumptions: assumptions,
            requiresEvidenceAbove: requiresEvidenceAbove,
            owner: owner,
            faces: faces,
            threatActors: threatActors
        )
    }

    /// Drops every action a file cannot mean, and keeps the edge that held it.
    ///
    /// These faults need the whole system: a label spans edges, and a blocker
    /// names an assumption declared elsewhere in the block.
    private mutating func checkedActions(
        on edges: [SourceMitigates],
        assumptions: [SourceAssumption]
    ) -> [SourceMitigates] {
        let declared = Set(assumptions.map(\.label))

        // Pass one: the faults an edge carries on its own.
        var kept: [SourceMitigates] = []
        for edge in edges {
            guard let action = edge.action else {
                kept.append(edge)
                continue
            }

            // An edge can trip more than one of these at once. Report the
            // first one this order finds, not every one it trips.
            var fault: String?
            if (edge.status ?? "adopted") != "assumed" {
                fault = "the mitigates edge \"\(edge.id)\" is adopted, so it carries no recommendation"
            } else if let text = action.text, text.allSatisfy(\.isWhitespace) {
                fault = "the action \"\(action.label)\" has no text"
            } else if let blocker = action.blockedBy, declared.contains(blocker) == false {
                fault = "the action \"\(action.label)\" is blocked by \"\(blocker)\", which no assumption declares"
            }

            if let fault {
                record(fault, severity: .warning)
                kept.append(edge.withoutAction())
            } else {
                kept.append(edge)
            }
        }

        // Pass two: one label states its text once, and states it at all.
        var stated: Set<String> = []
        var second: [String] = []
        for edge in kept {
            guard let action = edge.action, action.text != nil else { continue }
            if stated.insert(action.label).inserted == false { second.append(action.label) }
        }
        for label in Set(second) {
            record("the action \"\(label)\" states its text twice", severity: .warning)
        }

        let actionsStatingText = kept.compactMap(\.action).filter { $0.text != nil }
        let named = Set(actionsStatingText.map(\.label))
        let nameless = Set(kept.compactMap(\.action?.label)).subtracting(named)
        for label in nameless.sorted() {
            record("the action \"\(label)\" states no text", severity: .warning)
        }

        var seenText: Set<String> = []
        return kept.map { edge in
            guard let action = edge.action else { return edge }
            if nameless.contains(action.label) { return edge.withoutAction() }
            guard action.text != nil else { return edge }
            if seenText.insert(action.label).inserted { return edge }
            return edge.withoutAction()
        }
    }

    private mutating func parseAssumption() -> SourceAssumption? {
        advance()
        guard let label = expect(.string, "what the assumption is called") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var text: String?
        var owner: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "text": text = parseTextAttribute()
            case "owner": owner = parseTextAttribute()
            default:
                record("an assumption holds text and owner, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let text, text.isEmpty == false else {
            record("the assumption \"\(label.text)\" has no text", at: label)
            return nil
        }
        return SourceAssumption(label: label.text, text: text, owner: owner)
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
                    "a technology holds name, category, description, threats, encrypts and "
                        + "control, not \"\(current.text)\""
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

    private mutating func parseZone() -> SourceZone? {
        advance()
        guard let id = expect(.string, "the zone's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var kind = "private"
        var network = "generic"
        var name: String?
        var reducesRisk = true
        var reducesRiskBy: Int?
        var components: [SourceComponent] = []
        var boundary = "network"
        var description: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "kind":
                let token = current
                kind = parseTextAttribute() ?? kind
                expectVocabulary(kind, Self.zoneKinds, field: "kind", at: token)
            case "network":
                let token = current
                network = parseTextAttribute() ?? network
                expectVocabulary(network, Self.networks, field: "network", at: token)
            case "name":
                name = parseTextAttribute()
            case "reduces_risk":
                reducesRisk = parseBooleanAttribute() ?? true
            case "reduces_risk_by":
                let token = current
                reducesRiskBy = parseNumberAttribute()
                if let percent = reducesRiskBy, percent < 0 || percent > 100 {
                    record("reduces_risk_by is \(percent); it runs from 0 to 100", at: token)
                }
            case "component":
                if let component = parseComponent() { components.append(component) }
            case "boundary":
                let token = current
                boundary = parseTextAttribute() ?? boundary
                expectVocabulary(boundary, Self.boundaries, field: "boundary", at: token)
            case "description":
                description = parseTextAttribute()
            default:
                record("a zone holds kind, network, name, reduces_risk, reduces_risk_by, component, boundary and description, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceZone(
            id: id.text,
            kind: kind,
            network: network,
            name: name,
            reducesRisk: reducesRisk,
            reducesRiskBy: reducesRiskBy,
            components: components,
            boundary: boundary,
            description: description
        )
    }

    private mutating func parseComponent() -> SourceComponent? {
        advance()
        guard let id = expect(.string, "the component's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var technologyId: String?
        var name: String?
        var data = "internal"
        var raisesThreats = true
        var runsAs = "user"
        var shape: String?
        var assets: [SourceAsset] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "technology": technologyId = parseTextAttribute()
            case "name": name = parseTextAttribute()
            case "data":
                let token = current
                data = parseTextAttribute() ?? data
                // A classification word belongs to the project's scheme, and
                // a library states that scheme, which the parser has never
                // read. `ImportArchitecture` says what the scheme does not
                // hold, the way `LoadLibraries` says what the taxonomy does
                // not hold.
                _ = data
            case "threats": raisesThreats = parseBooleanAttribute() ?? true
            case "runs_as":
                let token = current
                runsAs = parseTextAttribute() ?? runsAs
                expectVocabulary(runsAs, Self.privilegeLevels, field: "runs_as", at: token)
            case "shape":
                let token = current
                shape = parseTextAttribute()
                expectVocabulary(shape ?? "", Self.diagramShapes, field: "shape", at: token)
            case "asset":
                if let asset = parseAsset() { assets.append(asset) }
            default:
                record("a component holds technology, name, data, threats, runs_as, shape and asset, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let technologyId else {
            record("the component \"\(id.text)\" names no technology", at: id)
            return nil
        }
        return SourceComponent(
            id: id.text,
            technologyId: technologyId,
            name: name,
            data: data,
            raisesThreats: raisesThreats,
            runsAs: runsAs,
            assets: assets,
            shape: shape
        )
    }

    private mutating func parseAsset() -> SourceAsset? {
        advance()
        guard let name = expect(.string, "the asset's name") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var data = "internal"
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "data":
                let token = current
                data = parseTextAttribute() ?? data
                // A classification word belongs to the project's scheme, and
                // a library states that scheme, which the parser has never
                // read. `ImportArchitecture` says what the scheme does not
                // hold, the way `LoadLibraries` says what the taxonomy does
                // not hold.
                _ = data
            default:
                record("an asset holds data, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")
        return SourceAsset(name: name.text, data: data)
    }

    private mutating func parseFlow() -> SourceFlow? {
        advance()
        guard let source = expect(.identifier, "the component the flow starts at") else { return nil }
        guard expect(.arrow, "->") != nil else { return nil }
        guard let target = expect(.identifier, "the component the flow ends at") else { return nil }
        guard current.kind == .leftBrace else {
            return SourceFlow(sourceId: source.text, targetId: target.text)
        }
        advance()

        var kind = "network"
        var description: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "kind":
                let token = current
                kind = parseTextAttribute() ?? kind
                expectVocabulary(kind, Self.flowKinds, field: "kind", at: token)
            case "description":
                description = parseTextAttribute()
            default:
                record("a flow holds kind and description, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceFlow(
            sourceId: source.text,
            targetId: target.text,
            kind: kind,
            description: description
        )
    }

    private mutating func parseMitigates() -> SourceMitigates? {
        advance()
        guard let source = expect(.identifier, "the component the mitigation comes from") else { return nil }
        guard expect(.arrow, "->") != nil else { return nil }
        guard let target = expect(.identifier, "the component the mitigation protects") else { return nil }
        let name = "\(source.text)->\(target.text)"
        guard expect(.leftBrace, "{") != nil else { return nil }

        var threatIds: [String] = []
        var reducesRiskBy: Int?
        var status: String?
        var action: SourceEdgeAction?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "threats":
                threatIds = parseListAttribute()
            case "reduces_risk_by":
                let token = current
                reducesRiskBy = parseNumberAttribute()
                if let percent = reducesRiskBy, percent < 0 || percent > 100 {
                    record("reduces_risk_by is \(percent); it runs from 0 to 100", at: token)
                }
            case "status":
                let token = current
                let raw = parseTextAttribute() ?? ""
                if MitigationStatus(rawValue: raw) == nil {
                    record(
                        "status is \"\(raw)\"; a mitigates edge is \"adopted\" or \"assumed\"",
                        at: token
                    )
                } else {
                    status = raw
                }
            case "recommendation":
                if let read = parseEdgeAction() { action = read }
            default:
                record("a mitigates edge holds threats, reduces_risk_by, status and recommendation, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard threatIds.isEmpty == false else {
            record("the mitigates edge \"\(name)\" names no threats", at: source)
            return nil
        }
        guard let reducesRiskBy else {
            record("the mitigates edge \"\(name)\" has no reduces_risk_by", at: source)
            return nil
        }
        return SourceMitigates(
            sourceId: source.text,
            targetId: target.text,
            threatIds: threatIds,
            reducesRiskBy: reducesRiskBy,
            status: status,
            action: action
        )
    }

    /// A recommendation on an assumed edge: what a team would do to adopt it.
    ///
    /// The faults that need every edge and every assumption in scope are
    /// reported once the whole system is read, not here.
    private mutating func parseEdgeAction() -> SourceEdgeAction? {
        advance()
        guard let label = expect(.string, "what the action is called") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var text: String?
        var note: String?
        var blockedBy: String?
        var sources: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "text": text = parseTextAttribute()
            case "note": note = parseTextAttribute()
            case "blocked_by": blockedBy = parseTextAttribute()
            case "sources": sources = parseListAttribute()
            default:
                record("a recommendation holds text, note, blocked_by and sources, not \"\(current.text)\"")
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceEdgeAction(
            label: label.text,
            text: text,
            note: note,
            blockedBy: blockedBy,
            sources: sources
        )
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

    // MARK: what the file must hold once it parses

    private mutating func check(_ source: ArchitectureSource) {
        var seen: Set<String> = []
        for id in source.technologies.map(\.id) + source.zones.map(\.id) {
            if seen.insert(id).inserted == false {
                record("\"\(id)\" is declared twice", at: tokens[0])
            }
        }

        var componentIds: Set<String> = []
        for component in source.everyComponent where componentIds.insert(component.id).inserted == false {
            record("the component \"\(component.id)\" is declared twice", at: tokens[0])
        }

        var pairs: Set<String> = []
        for flow in source.flows {
            if componentIds.contains(flow.sourceId) == false {
                record("the flow starts at \"\(flow.sourceId)\", which this file does not declare", at: tokens[0])
            }
            if componentIds.contains(flow.targetId) == false {
                record("the flow ends at \"\(flow.targetId)\", which this file does not declare", at: tokens[0])
            }
            if flow.sourceId == flow.targetId {
                record("the flow \"\(flow.id)\" starts and ends at the same component", at: tokens[0])
            }
            if pairs.insert(flow.id).inserted == false {
                record("the flow \"\(flow.id)\" is declared twice", at: tokens[0])
            }
        }

        for zone in source.zones where zone.components.isEmpty {
            record("the zone \"\(zone.id)\" holds no components", at: tokens[0], severity: .warning)
        }

        var edges: Set<String> = []
        for edge in source.mitigates {
            if componentIds.contains(edge.sourceId) == false {
                record("the mitigates edge starts at \"\(edge.sourceId)\", which this file does not declare", at: tokens[0])
            }
            if componentIds.contains(edge.targetId) == false {
                record("the mitigates edge ends at \"\(edge.targetId)\", which this file does not declare", at: tokens[0])
            }
            if edge.sourceId == edge.targetId {
                record("the mitigates edge \"\(edge.id)\" starts and ends at the same component", at: tokens[0])
            }
            if edges.insert(edge.id).inserted == false {
                record("the mitigates edge \"\(edge.id)\" is declared twice", at: tokens[0])
            }
        }

        var labels: Set<String> = []
        for assumption in source.assumptions where labels.insert(assumption.label).inserted == false {
            record("the assumption \"\(assumption.label)\" is declared twice", at: tokens[0])
        }
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

    private mutating func expectVocabulary(
        _ value: String,
        _ allowed: Set<String>,
        field: String,
        at token: Token
    ) {
        guard allowed.contains(value) == false else { return }
        record(
            "\(field) is \"\(value)\"; this application holds "
                + allowed.sorted().map { "\"\($0)\"" }.joined(separator: ", "),
            at: token
        )
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
