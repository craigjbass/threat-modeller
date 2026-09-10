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
    private static let sensitivities: Set<String> = [
        "public", "internal", "confidential", "restricted"
    ]
    private static let flowKinds: Set<String> = ["network", "ipc", "file", "syscall", "human"]
    private static let boundaries: Set<String> = ["network", "privilege"]
    private static let privilegeLevels: Set<String> = ["user", "admin", "root", "system", "kernel"]

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
            default:
                record("a system holds catalogue, technology, zone, component, flow and mitigates, not \"\(current.text)\"")
                skipToNextBlock()
            }
        }
        _ = expect(.rightBrace, "}")

        return ArchitectureSource(
            systemName: name.text,
            catalogueTag: catalogueTag,
            technologies: technologies,
            zones: zones,
            components: components,
            flows: flows,
            mitigates: mitigates
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

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "category": category = parseTextAttribute()
            case "description": description = parseTextAttribute() ?? ""
            case "threats": threatIds = parseListAttribute()
            case "encrypts": encrypts = parseBooleanAttribute() ?? false
            default:
                record("a technology holds name, category, description, threats and encrypts, not \"\(current.text)\"")
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
        var assets: [SourceAsset] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "technology": technologyId = parseTextAttribute()
            case "name": name = parseTextAttribute()
            case "data":
                let token = current
                data = parseTextAttribute() ?? data
                expectVocabulary(data, Self.sensitivities, field: "data", at: token)
            case "threats": raisesThreats = parseBooleanAttribute() ?? true
            case "runs_as":
                let token = current
                runsAs = parseTextAttribute() ?? runsAs
                expectVocabulary(runsAs, Self.privilegeLevels, field: "runs_as", at: token)
            case "asset":
                if let asset = parseAsset() { assets.append(asset) }
            default:
                record("a component holds technology, name, data, threats, runs_as and asset, not \"\(current.text)\"")
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
            assets: assets
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
                expectVocabulary(data, Self.sensitivities, field: "data", at: token)
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
            default:
                record("a mitigates edge holds threats and reduces_risk_by, not \"\(current.text)\"")
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
            reducesRiskBy: reducesRiskBy
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
