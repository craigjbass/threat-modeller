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
    private static let componentStatuses: Set<String> = ["live", "proposed"]

    /// `allowsPart` is true only when the caller is reading the files of one
    /// system. A file read on its own must still state a `system` block.
    mutating func parse(allowsPart: Bool = false) -> ArchitectureRead {
        // A file that opens with anything but `system` is a part of a split
        // system: it states blocks and no header. The merge decides whether
        // the system it belongs to holds a header at all.
        if allowsPart, current.text != "system" { return parsePart() }

        guard let system = parseSystem() else {
            return ArchitectureRead(source: nil, diagnostics: diagnostics)
        }
        check(system)
        return ArchitectureRead(
            source: diagnostics.contains { $0.severity == .error } ? nil : system,
            diagnostics: diagnostics
        )
    }

    /// A file of a split system that holds no `system` block.
    ///
    /// It reads the same blocks a system block holds, at the top level. The
    /// source it answers states no system name, and the merge takes the name
    /// from the header file.
    private mutating func parsePart() -> ArchitectureRead {
        guard let part = parseBlocks(named: MergedArchitecture.headerlessName) else {
            return ArchitectureRead(source: nil, diagnostics: diagnostics)
        }
        // The cross-file checks run over the merged source, so a part is not
        // checked on its own for a flow that names another file's component.
        checkWithinOneFile(part)
        return ArchitectureRead(
            source: diagnostics.contains { $0.severity == .error } ? nil : part,
            diagnostics: diagnostics
        )
    }

    // MARK: the blocks

    private mutating func parseSystem() -> ArchitectureSource? {
        guard expectKeyword("system") else { return nil }
        guard let name = expect(.string, "the system's name") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }
        return parseBlocks(named: name.text, insideABlock: true)
    }

    /// The blocks a system holds. `insideABlock` is true for a `system` block,
    /// which ends at its closing brace, and false for a part file, which ends
    /// at the end of the file.
    private mutating func parseBlocks(
        named name: String,
        insideABlock: Bool = false
    ) -> ArchitectureSource? {
        var catalogueTag: String?
        var technologies: [SourceTechnology] = []
        var zones: [SourceZone] = []
        var components: [SourceComponent] = []
        var flows: [SourceFlow] = []
        var mitigates: [SourceMitigates] = []
        var riskTolerance: String?
        var assumptions: [SourceAssumption] = []
        var useCases: [SourceUseCase] = []
        var exclusions: [SourceExclusion] = []
        var systemAssets: [SourceSystemAsset] = []
        var thirdParties: [SourceThirdParty] = []
        var diagrams: [SourceDiagram] = []
        var faces: [String] = []
        var requiresEvidenceAbove: String?
        var owner: String?
        var threatActors: [SourceThreatActor] = []
        var description: String?
        var authors: [String] = []
        var links: [String] = []
        var repositories: [String] = []
        var created: String?
        var reviewed: String?
        var version: String?
        var attributes: [SourceSystemAttribute] = []
        var users: [SourceUser] = []

        while current.kind != .endOfFile && (insideABlock == false || current.kind != .rightBrace) {
            switch current.text {
            case "catalogue":
                catalogueTag = parseTextAttribute()
            case "technology":
                if let technology = parseTechnology() { technologies.append(technology) }
            case "zone":
                if let zone = parseZone() { zones.append(zone) }
            case "component":
                if let component = parseComponent() { components.append(component) }
            case "user":
                if let user = parseUser() { users.append(user) }
            case "asset":
                if let asset = parseSystemAsset() { systemAssets.append(asset) }
            case "third_party":
                if let party = parseThirdParty() { thirdParties.append(party) }
            case "diagram":
                if let diagram = parseDiagram() { diagrams.append(diagram) }
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
            case "use_case":
                if let useCase = parseUseCase() { useCases.append(useCase) }
            case "exclusion":
                if let exclusion = parseExclusion() { exclusions.append(exclusion) }
            case "owner":
                owner = parseTextAttribute()
            case "description":
                description = parseTextAttribute()
            case "authors":
                authors = parseListAttribute()
            case "links":
                links = parseUrlListAttribute("links")
            case "repositories":
                repositories = parseUrlListAttribute("repositories")
            case "created":
                created = parseDateAttribute("created")
            case "reviewed":
                reviewed = parseDateAttribute("reviewed")
            case "version":
                version = parseTextAttribute()
            case "attribute":
                let token = current
                if let attribute = parseSystemAttribute() {
                    if attributes.contains(where: { $0.name == attribute.name }) {
                        record(
                            "the attribute \"\(attribute.name)\" is declared twice",
                            at: token
                        )
                    } else {
                        attributes.append(attribute)
                    }
                }
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
                record(LanguageBlockId.archSystem.unknownAttribute(current.text))
                skipToNextBlock()
            }
        }
        if insideABlock { _ = expect(.rightBrace, "}") }

        let checked = checkedActions(on: mitigates, assumptions: assumptions)
        let everyComponent = components + zones.flatMap(\.components)
        checkExclusions(exclusions, against: everyComponent)
        checkAssets(systemAssets, components: everyComponent, flows: flows)
        checkThirdParties(thirdParties, components: everyComponent, assumptions: assumptions)

        return ArchitectureSource(
            systemName: name,
            catalogueTag: catalogueTag,
            technologies: technologies,
            zones: zones,
            components: components,
            flows: flows,
            mitigates: checked,
            riskTolerance: riskTolerance,
            assumptions: assumptions,
            useCases: useCases,
            exclusions: exclusions,
            systemAssets: systemAssets,
            thirdParties: thirdParties,
            diagrams: diagrams,
            requiresEvidenceAbove: requiresEvidenceAbove,
            owner: owner,
            faces: faces,
            threatActors: threatActors,
            description: description,
            authors: authors,
            links: links,
            repositories: repositories,
            created: created,
            reviewed: reviewed,
            version: version,
            attributes: attributes,
            users: users
        )
    }

    /// A `user` block: one human who uses the system. The user block design
    /// states the attributes.
    private mutating func parseUser() -> SourceUser? {
        advance()
        guard let id = expect(.string, "the user's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var role = ""
        var access = SourceUser.defaultAccess
        var uses: [String] = []
        var reaches: [String] = []
        var threatActorId: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "role": role = parseTextAttribute() ?? role
            case "access":
                let token = current
                access = parseTextAttribute() ?? access
                expectVocabulary(access, Self.privilegeLevels, field: "access", at: token)
            case "uses": uses = parseListAttribute()
            case "reaches": reaches = parseListAttribute()
            case "threat_actor": threatActorId = parseTextAttribute()
            default:
                record(LanguageBlockId.archUser.unknownAttribute(current.text))
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceUser(
            id: id.text,
            name: name,
            role: role,
            access: access,
            uses: uses,
            reaches: reaches,
            threatActorId: threatActorId
        )
    }

    /// A date the file states, or nil when it states something that is not
    /// one. A date reads `YYYY-MM-DD` and names a day of the calendar.
    private mutating func parseDateAttribute(_ name: String) -> String? {
        let token = current
        guard let raw = parseTextAttribute() else { return nil }
        switch GovernanceDate.read(raw) {
        case .success:
            return raw
        case .failure(let fault):
            record(fault.message(attribute: name, raw: raw), at: token)
            return nil
        }
    }

    /// A list of addresses. Something that is not one is a fault naming it.
    private mutating func parseUrlListAttribute(_ name: String) -> [String] {
        let token = current
        let held = parseListAttribute()
        return held.filter { address in
            guard address.hasPrefix("https://") || address.hasPrefix("http://") else {
                record(
                    "\(name) holds \"\(address)\", which is not an address; "
                        + "an address starts https:// or http://",
                    at: token
                )
                return false
            }
            return true
        }
    }

    /// One thing a team states that the language does not name.
    private mutating func parseSystemAttribute() -> SourceSystemAttribute? {
        advance()
        guard let name = expect(.string, "the attribute's name") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var value: String?
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "value": value = parseTextAttribute()
            default:
                record(LanguageBlockId.archAttribute.unknownAttribute(current.text))
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let value else {
            record("the attribute \"\(name.text)\" states no value", at: name)
            return nil
        }
        return SourceSystemAttribute(name: name.text, value: value)
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
                record(LanguageBlockId.archAssumption.unknownAttribute(current.text))
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

    /// A thing both drawn and excluded is a contradiction, so an exclusion
    /// whose label names a component the same system draws is a warning.
    private mutating func checkExclusions(
        _ exclusions: [SourceExclusion],
        against components: [SourceComponent]
    ) {
        var names: Set<String> = []
        for component in components {
            names.insert(component.id.lowercased())
            if let name = component.name { names.insert(name.lowercased()) }
        }
        for exclusion in exclusions where names.contains(exclusion.label.lowercased()) {
            record(
                "the exclusion \"\(exclusion.label)\" names a component this system draws; "
                    + "a thing both drawn and excluded is a contradiction",
                severity: .warning
            )
        }
    }

    static let diagramKinds: Set<String> = ["mermaid", "d2"]

    /// A `diagram` block: one picture the team keeps beside the diagram the
    /// canvas draws.
    private mutating func parseDiagram() -> SourceDiagram? {
        advance()
        guard let label = expect(.string, "what the diagram is called") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var kind = "mermaid"
        var text: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "kind":
                let token = current
                kind = parseTextAttribute() ?? kind
                expectVocabulary(kind, Self.diagramKinds, field: "kind", at: token)
            case "text": text = parseTextAttribute()
            default:
                record(LanguageBlockId.archDiagram.unknownAttribute(current.text))
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let text, text.contains(where: { $0.isWhitespace == false }) else {
            record("the diagram \"\(label.text)\" has no text", at: label)
            return nil
        }
        return SourceDiagram(label: label.text, kind: kind, text: text)
    }

    static let thirdPartyKinds: Set<String> = ["saas", "open_source", "infrastructure", "contractor"]
    static let uptimeDependencies: Set<String> = ["none", "degraded", "hard", "operational"]

    /// A `third_party` block: one party outside this team the system depends
    /// on.
    private mutating func parseThirdParty() -> SourceThirdParty? {
        advance()
        guard let id = expect(.string, "the third party's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var description = ""
        var kind = "saas"
        var payingCustomer = false
        var uptime: String?
        var uptimeNotes = ""
        var owner: String?
        var link: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            case "description": description = parseTextAttribute() ?? description
            case "kind":
                let token = current
                kind = parseTextAttribute() ?? kind
                expectVocabulary(kind, Self.thirdPartyKinds, field: "kind", at: token)
            case "paying_customer": payingCustomer = parseBooleanAttribute() ?? payingCustomer
            case "uptime":
                let token = current
                let raw = parseTextAttribute() ?? ""
                expectVocabulary(raw, Self.uptimeDependencies, field: "uptime", at: token)
                uptime = raw
            case "uptime_notes": uptimeNotes = parseTextAttribute() ?? uptimeNotes
            case "owner": owner = parseTextAttribute()
            case "link": link = parseTextAttribute()
            default:
                record(LanguageBlockId.archThirdParty.unknownAttribute(current.text))
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let name, name.isEmpty == false else {
            record("the third party \"\(id.text)\" has no name", at: id)
            return nil
        }
        guard let uptime, uptime.isEmpty == false else {
            record(
                "the third party \"\(id.text)\" states no uptime; state \"none\", "
                    + "\"degraded\", \"hard\" or \"operational\"",
                at: id
            )
            return nil
        }
        return SourceThirdParty(
            id: id.text,
            name: name,
            description: description,
            kind: kind,
            payingCustomer: payingCustomer,
            uptime: uptime,
            uptimeNotes: uptimeNotes,
            owner: owner,
            link: link
        )
    }

    /// A `provided_by` naming nothing is an error. A party this system cannot
    /// run without, and that no assumption names, is a warning: a dependency
    /// nobody has thought about is the one that fails.
    private mutating func checkThirdParties(
        _ parties: [SourceThirdParty],
        components: [SourceComponent],
        assumptions: [SourceAssumption]
    ) {
        let declared = Set(parties.map(\.id))
        for component in components {
            guard let provider = component.providedBy else { continue }
            guard declared.contains(provider) == false else { continue }
            record(
                "the component \"\(component.id)\" is provided by \"\(provider)\", "
                    + "which no third_party declares"
            )
        }

        let said = assumptions.map { "\($0.label) \($0.text)".lowercased() }
        for party in parties where party.uptime == "hard" {
            let names = [party.id.lowercased(), party.name.lowercased()]
            guard said.contains(where: { text in names.contains(where: text.contains) }) == false
            else { continue }
            record(
                "this system cannot run without \"\(party.name)\" and no assumption names it",
                severity: .warning
            )
        }
    }

    /// An `asset` block on a system: one named thing of value.
    private mutating func parseSystemAsset() -> SourceSystemAsset? {
        advance()
        guard let id = expect(.string, "the asset's identifier") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var name: String?
        var classification = "internal"
        var description = ""
        var owner: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "name": name = parseTextAttribute()
            // A classification word belongs to the project's scheme, and a
            // library states that scheme, which the parser has never read.
            // `ImportArchitecture` says what the scheme does not hold.
            case "classification": classification = parseTextAttribute() ?? classification
            case "description": description = parseTextAttribute() ?? description
            case "owner": owner = parseTextAttribute()
            default:
                record(LanguageBlockId.archSystemAsset.unknownAttribute(current.text))
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let name, name.isEmpty == false else {
            record("the asset \"\(id.text)\" has no name", at: id)
            return nil
        }
        return SourceSystemAsset(
            id: id.text,
            name: name,
            classification: classification,
            description: description,
            owner: owner
        )
    }

    /// What a component holds and what a flow carries must name an asset the
    /// system declares, and a flow must carry what its own end holds.
    private mutating func checkAssets(
        _ assets: [SourceSystemAsset],
        components: [SourceComponent],
        flows: [SourceFlow]
    ) {
        let declared = Set(assets.map(\.id))
        var holdsById: [String: Set<String>] = [:]
        for component in components {
            holdsById[component.id] = Set(component.holds)
            for held in component.holds where declared.contains(held) == false {
                record(
                    "the component \"\(component.id)\" holds \"\(held)\", which no asset declares"
                )
            }
        }
        for flow in flows {
            for carried in flow.carries {
                guard declared.contains(carried) else {
                    record(
                        "the flow \"\(flow.id)\" carries \"\(carried)\", which no asset declares"
                    )
                    continue
                }
                guard let held = holdsById[flow.sourceId] else { continue }
                if held.contains(carried) == false {
                    record(
                        "the flow \"\(flow.id)\" carries \"\(carried)\", which the component "
                            + "\"\(flow.sourceId)\" does not hold",
                        severity: .warning
                    )
                }
            }
        }
    }

    /// A `use_case` block: what a person does with the system.
    private mutating func parseUseCase() -> SourceUseCase? {
        advance()
        guard let label = expect(.string, "what the use case is called") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var text: String?
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "text": text = parseTextAttribute()
            default:
                record(LanguageBlockId.archUseCase.unknownAttribute(current.text))
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let text, text.isEmpty == false else {
            record("the use_case \"\(label.text)\" has no text", at: label)
            return nil
        }
        return SourceUseCase(label: label.text, text: text)
    }

    /// An `exclusion` block: what this model does not cover, and why.
    ///
    /// A rationale is required. An exclusion with no reason is a gap, and a
    /// reader cannot tell a decision from an oversight.
    private mutating func parseExclusion() -> SourceExclusion? {
        advance()
        guard let label = expect(.string, "what the exclusion is called") else { return nil }
        guard expect(.leftBrace, "{") != nil else { return nil }

        var text: String?
        var rationale: String?
        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "text": text = parseTextAttribute()
            case "rationale": rationale = parseTextAttribute()
            default:
                record(LanguageBlockId.archExclusion.unknownAttribute(current.text))
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        guard let text, text.isEmpty == false else {
            record("the exclusion \"\(label.text)\" has no text", at: label)
            return nil
        }
        guard let rationale, rationale.isEmpty == false else {
            record(
                "the exclusion \"\(label.text)\" has no rationale; an exclusion with no "
                    + "reason is a gap",
                at: label
            )
            return nil
        }
        return SourceExclusion(label: label.text, text: text, rationale: rationale)
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
                record(LanguageBlockId.archThreatActor.unknownAttribute(current.text))
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
                record(LanguageBlockId.archTechnology.unknownAttribute(current.text))
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
        var zoneSource: String?
        var tags: [String] = []

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
                let token = current
                if let component = parseComponent() {
                    // A nested component sits in this zone. One that states
                    // another zone says two things at once.
                    if let stated = component.zoneId, stated != id.text {
                        record(
                            "the component \"\(component.id)\" sits in the zone \"\(id.text)\" "
                                + "and states zone \"\(stated)\"",
                            at: token
                        )
                    }
                    components.append(component)
                }
            case "boundary":
                let token = current
                boundary = parseTextAttribute() ?? boundary
                expectVocabulary(boundary, Self.boundaries, field: "boundary", at: token)
            case "description":
                description = parseTextAttribute()
            case "source":
                zoneSource = parseTextAttribute()
            case "tags":
                tags = parseListAttribute()
            default:
                record(LanguageBlockId.archZone.unknownAttribute(current.text))
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
            description: description,
            source: zoneSource,
            tags: tags
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
        var holds: [String] = []
        var providedBy: String?
        var source: String?
        var declaredData: String?
        var tags: [String] = []
        var status = "live"
        var version = ""
        var cves: [String] = []
        var zoneId: String?

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "technology": technologyId = parseTextAttribute()
            case "name": name = parseTextAttribute()
            case "zone": zoneId = parseTextAttribute()
            case "holds":
                holds = parseListAttribute()
            case "provided_by":
                providedBy = parseTextAttribute()
            case "source":
                source = parseTextAttribute()
            case "data":
                let token = current
                data = parseTextAttribute() ?? data
                declaredData = data
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
            case "tags":
                tags = parseListAttribute()
            case "status":
                let token = current
                status = parseTextAttribute() ?? status
                expectVocabulary(status, Self.componentStatuses, field: "status", at: token)
            case "version":
                version = parseTextAttribute() ?? version
            case "cves":
                let token = current
                cves = []
                for word in parseListAttribute() {
                    // A word that is not a CVE id is an error; one stated
                    // twice is a warning, and the second is dropped.
                    guard CveId.isValid(word) else {
                        record(
                            "the component \"\(id.text)\" states cves \"\(word)\", "
                                + "which is not a CVE id",
                            at: token
                        )
                        continue
                    }
                    guard cves.contains(word) == false else {
                        record(
                            "the component \"\(id.text)\" states \"\(word)\" twice",
                            at: token,
                            severity: .warning
                        )
                        continue
                    }
                    cves.append(word)
                }
            default:
                record(LanguageBlockId.archComponent.unknownAttribute(current.text))
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
            holds: holds,
            providedBy: providedBy,
            source: source,
            declaredData: declaredData,
            shape: shape,
            tags: tags,
            status: status,
            zoneId: zoneId,
            version: version,
            cves: cves
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
                record(LanguageBlockId.archComponentAsset.unknownAttribute(current.text))
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
        var carries: [String] = []
        var tags: [String] = []

        while current.kind != .rightBrace && current.kind != .endOfFile {
            switch current.text {
            case "kind":
                let token = current
                kind = parseTextAttribute() ?? kind
                expectVocabulary(kind, Self.flowKinds, field: "kind", at: token)
            case "description":
                description = parseTextAttribute()
            case "carries":
                carries = parseListAttribute()
            case "tags":
                tags = parseListAttribute()
            default:
                record(LanguageBlockId.archFlow.unknownAttribute(current.text))
                skipAttribute()
            }
        }
        _ = expect(.rightBrace, "}")

        return SourceFlow(
            sourceId: source.text,
            targetId: target.text,
            kind: kind,
            description: description,
            carries: carries,
            tags: tags
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
                record(LanguageBlockId.archMitigates.unknownAttribute(current.text))
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
                record(LanguageBlockId.archRecommendation.unknownAttribute(current.text))
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

    /// The checks one file can run on its own.
    ///
    /// A part file of a split system states a flow that may name a component
    /// another file declares, so the checks that read one identifier against
    /// another run over the merged source and not here.
    private mutating func checkWithinOneFile(_ source: ArchitectureSource) {
        var seen: Set<String> = []
        for id in source.technologies.map(\.id) + source.zones.map(\.id) {
            if seen.insert(id).inserted == false {
                record("\"\(id)\" is declared twice", at: tokens[0])
            }
        }

        var componentIds: Set<String> = []
        for component in source.everyComponent
        where componentIds.insert(component.id).inserted == false {
            record("the component \"\(component.id)\" is declared twice", at: tokens[0])
        }
        checkUserIds(source.users, against: componentIds)

        var pairs: Set<String> = []
        for flow in source.flows {
            if flow.sourceId == flow.targetId {
                record(
                    "the flow \"\(flow.id)\" starts and ends at the same component",
                    at: tokens[0]
                )
            }
            if pairs.insert(flow.id).inserted == false {
                record("the flow \"\(flow.id)\" is declared twice", at: tokens[0])
            }
        }

        var edges: Set<String> = []
        for edge in source.mitigates {
            if edge.sourceId == edge.targetId {
                record(
                    "the mitigates edge \"\(edge.id)\" starts and ends at the same component",
                    at: tokens[0]
                )
            }
            if edges.insert(edge.id).inserted == false {
                record("the mitigates edge \"\(edge.id)\" is declared twice", at: tokens[0])
            }
        }

        var labels: Set<String> = []
        for assumption in source.assumptions
        where labels.insert(assumption.label).inserted == false {
            record("the assumption \"\(assumption.label)\" is declared twice", at: tokens[0])
        }
    }

    /// A user and a component share one namespace, because a flow names
    /// either one at an end.
    private mutating func checkUserIds(_ users: [SourceUser], against componentIds: Set<String>) {
        var userIds: Set<String> = []
        for user in users {
            if userIds.insert(user.id).inserted == false {
                record("the user \"\(user.id)\" is declared twice", at: tokens[0])
            } else if componentIds.contains(user.id) {
                record("\"\(user.id)\" is declared as a component and as a user", at: tokens[0])
            }
        }
    }

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
        checkUserIds(source.users, against: componentIds)

        // A whole file declares every component a user reaches and every
        // client a user holds. A part file leaves that to the merge. A user
        // is not a component, so a user holding a user is refused here too.
        for user in source.users {
            for client in user.uses where componentIds.contains(client) == false {
                record(
                    "the user \"\(user.id)\" uses \"\(client)\", which this file does not declare",
                    at: tokens[0]
                )
            }
            for reached in user.reaches where componentIds.contains(reached) == false {
                record(
                    "the user \"\(user.id)\" reaches \"\(reached)\", which this file does not declare",
                    at: tokens[0]
                )
            }
        }
        // A flow and a mitigates edge name a component or a user at an end.
        componentIds.formUnion(source.users.map(\.id))

        // A whole file declares every zone it holds, so a stated zone it does
        // not declare is known here. A part file leaves that to the merge.
        let zoneIds = Set(source.zones.map(\.id))
        for component in source.components {
            if let stated = component.zoneId, zoneIds.contains(stated) == false {
                record(
                    "the component \"\(component.id)\" states zone \"\(stated)\", which this file "
                        + "does not declare",
                    at: tokens[0]
                )
            }
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
