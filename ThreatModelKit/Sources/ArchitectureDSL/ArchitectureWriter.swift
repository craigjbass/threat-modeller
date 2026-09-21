import ThreatModelKit

/// Writes an architecture source in the canonical shape.
///
/// Two-space indentation, attributes aligned on the equals sign inside one
/// block, a blank line between blocks, and the block order technologies, zones,
/// components, users, flows. A rewrite of an unchanged source produces no diff.
struct ArchitectureWriter {
    /// Writes a source with a fresh writer. A convenience for call sites
    /// that hold no writer instance of their own.
    static func text(of source: ArchitectureSource) -> String {
        ArchitectureWriter().write(source)
    }

    func write(_ source: ArchitectureSource) -> String {
        write(source, asPart: false)
    }

    /// One file of a split system: the same blocks, at the top level, with no
    /// `system` block around them.
    func writePart(_ source: ArchitectureSource) -> String {
        write(source, asPart: true)
    }

    private func write(_ source: ArchitectureSource, asPart: Bool) -> String {
        var lines: [String] = []
        if asPart == false { lines.append("system \(quoted(source.systemName)) {") }

        var body: [String] = []

        // Document control first, in the order a reader reads it: what the
        // system is, who owns it, who wrote it, which version, when.
        var control: [(String, String)] = []
        if let description = source.description {
            control.append(("description", quoted(description)))
        }
        if let owner = source.owner { control.append(("owner", quoted(owner))) }
        if source.authors.isEmpty == false {
            control.append(("authors", list(source.authors)))
        }
        if let version = source.version { control.append(("version", quoted(version))) }
        if let created = source.created { control.append(("created", quoted(created))) }
        if let reviewed = source.reviewed { control.append(("reviewed", quoted(reviewed))) }
        if source.links.isEmpty == false { control.append(("links", list(source.links))) }
        if source.repositories.isEmpty == false {
            control.append(("repositories", list(source.repositories)))
        }
        if control.isEmpty == false {
            body += aligned(control)
            body.append("")
        }

        for attribute in source.attributes {
            body.append("attribute \(quoted(attribute.name)) {")
            body += indent(aligned([("value", quoted(attribute.value))]))
            body.append("}")
            body.append("")
        }

        if let riskTolerance = source.riskTolerance {
            body += aligned([("risk_tolerance", quoted(riskTolerance))])
            body.append("")
        }

        for assumption in source.assumptions {
            body.append("assumption \(quoted(assumption.label)) {")
            var attributes: [(String, String)] = [("text", quoted(assumption.text))]
            if let owner = assumption.owner {
                attributes.append(("owner", quoted(owner)))
            }
            body += indent(aligned(attributes))
            body.append("}")
            body.append("")
        }

        for useCase in source.useCases {
            body.append("use_case \(quoted(useCase.label)) {")
            body += indent(aligned([("text", quoted(useCase.text))]))
            body.append("}")
            body.append("")
        }

        for exclusion in source.exclusions {
            body.append("exclusion \(quoted(exclusion.label)) {")
            body += indent(
                aligned([
                    ("text", quoted(exclusion.text)),
                    ("rationale", quoted(exclusion.rationale))
                ])
            )
            body.append("}")
            body.append("")
        }

        if let catalogueTag = source.catalogueTag {
            body += aligned([("catalogue", quoted(catalogueTag))])
            body.append("")
        }

        if let requiresEvidenceAbove = source.requiresEvidenceAbove {
            body += aligned([("requires_evidence_above", quoted(requiresEvidenceAbove))])
            body.append("")
        }

        if source.faces.isEmpty == false {
            body += aligned([("faces", "[" + source.faces.map(quoted).joined(separator: ", ") + "]")])
            body.append("")
        }

        for clearance in source.clearances {
            body.append("clearance \(quoted(clearance.id)) {")
            var attributes: [(String, String)] = [("name", quoted(clearance.name))]
            if clearance.description.isEmpty == false {
                attributes.append(("description", quoted(clearance.description)))
            }
            attributes.append(
                ("reduces_insider_risk_by", String(clearance.reducesInsiderRiskBy))
            )
            attributes.append(("rationale", quoted(clearance.rationale)))
            if clearance.sources.isEmpty == false {
                attributes.append(
                    ("sources", "[" + clearance.sources.map(quoted).joined(separator: ", ") + "]")
                )
            }
            body += indent(aligned(attributes))
            body.append("}")
            body.append("")
        }

        for actor in source.threatActors {
            body.append("threat_actor \(quoted(actor.id)) {")
            var attributes: [(String, String)] = [("name", quoted(actor.name))]
            if actor.description.isEmpty == false {
                attributes.append(("description", quoted(actor.description)))
            }
            if actor.aliases.isEmpty == false {
                attributes.append(
                    ("aliases", "[" + actor.aliases.map(quoted).joined(separator: ", ") + "]")
                )
            }
            if let capability = actor.capability {
                attributes.append(("capability", quoted(capability)))
            }
            if actor.intent.isEmpty == false {
                attributes.append(("intent", quoted(actor.intent)))
            }
            if actor.performs.isEmpty == false {
                attributes.append(
                    ("performs", "[" + actor.performs.map(quoted).joined(separator: ", ") + "]")
                )
            }
            if actor.techniques.isEmpty == false {
                attributes.append(
                    ("techniques", "[" + actor.techniques.map(quoted).joined(separator: ", ") + "]")
                )
            }
            if let tier = actor.performsCatalogueTier {
                attributes.append(("performs_catalogue_tier", quoted(tier)))
            }
            body += indent(aligned(attributes))
            body.append("}")
            body.append("")
        }


        for technology in source.technologies {
            body.append("technology \(quoted(technology.id)) {")
            var attributes: [(String, String)] = [
                ("name", quoted(technology.name)),
                ("category", quoted(technology.category))
            ]
            if technology.description.isEmpty == false {
                attributes.append(("description", quoted(technology.description)))
            }
            if technology.threatIds.isEmpty == false {
                attributes.append(
                    ("threats", "[" + technology.threatIds.map(quoted).joined(separator: ", ") + "]")
                )
            }
            if technology.encrypts {
                attributes.append(("encrypts", "true"))
            }
            body += indent(aligned(attributes))
            for control in technology.controlDescriptions {
                body.append("  control \(quoted(control))")
            }
            body.append("}")
            body.append("")
        }

        for zone in source.zones {
            body.append("zone \(quoted(zone.id)) {")
            var attributes: [(String, String)] = [
                ("kind", quoted(zone.kind)),
                ("network", quoted(zone.network))
            ]
            if let name = zone.name { attributes.append(("name", quoted(name))) }
            if zone.reducesRisk == false { attributes.append(("reduces_risk", "false")) }
            if let percent = zone.reducesRiskBy {
                attributes.append(("reduces_risk_by", String(percent)))
            }
            if zone.boundary != "network" { attributes.append(("boundary", quoted(zone.boundary))) }
            if let description = zone.description {
                attributes.append(("description", quoted(description)))
            }
            if let source = zone.source {
                attributes.append(("source", quoted(source)))
            }
            if zone.tags.isEmpty == false {
                attributes.append(("tags", list(zone.tags)))
            }
            body += indent(aligned(attributes))

            for component in zone.components {
                body.append("")
                body += indent(componentBlock(component))
            }
            body.append("}")
            body.append("")
        }

        for asset in source.systemAssets {
            body.append("asset \(quoted(asset.id)) {")
            var attributes: [(String, String)] = [("name", quoted(asset.name))]
            attributes.append(("classification", quoted(asset.classification)))
            if asset.description.isEmpty == false {
                attributes.append(("description", quoted(asset.description)))
            }
            if let owner = asset.owner {
                attributes.append(("owner", quoted(owner)))
            }
            body += indent(aligned(attributes))
            body.append("}")
            body.append("")
        }

        for diagram in source.diagrams {
            body.append("diagram \(quoted(diagram.label)) {")
            body.append("  kind = \(quoted(diagram.kind))")
            body.append("  text = <<EOT")
            body += diagram.text
                .split(separator: "\n", omittingEmptySubsequences: false)
                .map { Self.verbatimMark + $0 }
            if diagram.text.hasSuffix("\n") { body.removeLast() }
            body.append(Self.verbatimMark + "EOT")
            body.append("}")
            body.append("")
        }

        for party in source.thirdParties {
            body.append("third_party \(quoted(party.id)) {")
            var attributes: [(String, String)] = [("name", quoted(party.name))]
            if party.description.isEmpty == false {
                attributes.append(("description", quoted(party.description)))
            }
            attributes.append(("kind", quoted(party.kind)))
            if party.payingCustomer { attributes.append(("paying_customer", "true")) }
            attributes.append(("uptime", quoted(party.uptime)))
            if party.uptimeNotes.isEmpty == false {
                attributes.append(("uptime_notes", quoted(party.uptimeNotes)))
            }
            if let owner = party.owner { attributes.append(("owner", quoted(owner))) }
            if let link = party.link { attributes.append(("link", quoted(link))) }
            body += indent(aligned(attributes))
            body.append("}")
            body.append("")
        }

        for component in source.components {
            body += componentBlock(component, statesZone: true)
            body.append("")
        }

        // A user sits in no zone, so every user block is a top-level block.
        // An attribute holding its default writes no line.
        //
        // The clients a user holds are written in the order the system
        // declares them, so two files that state the same set write the
        // same bytes. A client declared in another part file follows, in
        // the order stated.
        let declarationOrder = Dictionary(
            source.everyComponent.enumerated().map { ($0.element.id, $0.offset) },
            uniquingKeysWith: { first, _ in first }
        )
        for user in source.users {
            body.append("\(user.isAdversary ? "adversary" : "user") \(quoted(user.id)) {")
            var attributes: [(String, String)] = []
            if let name = user.name { attributes.append(("name", quoted(name))) }
            if user.role.isEmpty == false { attributes.append(("role", quoted(user.role))) }
            if user.access != SourceUser.defaultAccess {
                attributes.append(("access", quoted(user.access)))
            }
            let rank: (String) -> Int = { declarationOrder[$0] ?? Int.max }
            let declared = user.uses.enumerated().sorted { one, other in
                let first = rank(one.element.clientId)
                let second = rank(other.element.clientId)
                return first == second ? one.offset < other.offset : first < second
            }.map { $0.element }
            let statesAPath = declared.contains { $0.reaches.isEmpty == false }
            if statesAPath == false && declared.isEmpty == false {
                attributes.append(("uses", list(declared.map(\.clientId))))
            }
            if user.reaches.isEmpty == false { attributes.append(("reaches", list(user.reaches))) }
            if let actorId = user.threatActorId {
                attributes.append(("threat_actor", quoted(actorId)))
            }
            if let clearanceId = user.clearanceId {
                attributes.append(("clearance", quoted(clearanceId)))
            }
            body += indent(aligned(attributes))
            if statesAPath {
                for use in declared {
                    body.append("")
                    body.append("  uses \(quoted(use.clientId)) {")
                    if use.reaches.isEmpty == false {
                        body.append("    reaches = \(list(use.reaches))")
                    }
                    body.append("  }")
                }
            }
            body.append("}")
            body.append("")
        }

        for flow in source.flows {
            if flow.kind == "network" && flow.description == nil && flow.carries.isEmpty
                && flow.tags.isEmpty {
                body.append("flow \(flow.sourceId) -> \(flow.targetId)")
                continue
            }
            body.append("flow \(flow.sourceId) -> \(flow.targetId) {")
            var attributes: [(String, String)] = [("kind", quoted(flow.kind))]
            if let description = flow.description {
                attributes.append(("description", quoted(description)))
            }
            if flow.carries.isEmpty == false {
                attributes.append(
                    ("carries", "[" + flow.carries.map(quoted).joined(separator: ", ") + "]")
                )
            }
            if flow.tags.isEmpty == false {
                attributes.append(("tags", list(flow.tags)))
            }
            body += indent(aligned(attributes))
            body.append("}")
            body.append("")
        }
        if source.flows.isEmpty == false && body.last != "" { body.append("") }

        for edge in source.mitigates {
            // An edge that states nothing but its pair writes no body, the way
            // a network flow does.
            guard edge.status != nil || edge.action != nil else {
                body.append("mitigates \(edge.sourceId) -> \(edge.targetId)")
                body.append("")
                continue
            }
            body.append("mitigates \(edge.sourceId) -> \(edge.targetId) {")
            var attributes: [(String, String)] = []
            if let status = edge.status {
                attributes.append(("status", quoted(status)))
            }
            body += indent(aligned(attributes))
            if let action = edge.action {
                body.append("")
                body.append("  recommendation \(quoted(action.label)) {")
                var actionAttributes: [(String, String)] = []
                if let text = action.text { actionAttributes.append(("text", quoted(text))) }
                if let note = action.note { actionAttributes.append(("note", quoted(note))) }
                if let blockedBy = action.blockedBy {
                    actionAttributes.append(("blocked_by", quoted(blockedBy)))
                }
                if action.sources.isEmpty == false {
                    actionAttributes.append(
                        ("sources", "[" + action.sources.map(quoted).joined(separator: ", ") + "]")
                    )
                }
                body += indent(indent(aligned(actionAttributes)))
                body.append("  }")
            }
            body.append("}")
            body.append("")
        }

        while body.last == "" { body.removeLast() }
        if asPart {
            lines += body
        } else {
            lines += indent(body)
            lines.append("}")
        }
        return lines
            .map { $0.hasPrefix(Self.verbatimMark) ? String($0.dropFirst()) : $0 }
            .joined(separator: "\n") + "\n"
    }

    /// `statesZone` is true for a top-level block, which states the zone it
    /// sits in with a `zone` line. A nested block sits in the zone around it
    /// and writes no line.
    private func componentBlock(
        _ component: SourceComponent,
        statesZone: Bool = false
    ) -> [String] {
        var lines = ["component \(quoted(component.id)) {"]
        var attributes: [(String, String)] = [("technology", quoted(component.technologyId))]
        if let name = component.name { attributes.append(("name", quoted(name))) }
        if statesZone, let zoneId = component.zoneId {
            attributes.append(("zone", quoted(zoneId)))
        }
        // A component that states no classification of its own writes no
        // `data` line: the assets it holds decide, and writing the derived
        // word would make a file that says two things.
        if let declared = component.declaredData {
            attributes.append(("data", quoted(declared)))
        }
        // A live component writes no line, so every file written before the
        // attribute writes back byte for byte.
        if component.status != "live" {
            attributes.append(("status", quoted(component.status)))
        }
        // A component stating no version and no CVE writes neither line, so
        // every file written before the two attributes writes back byte for
        // byte.
        if component.version.isEmpty == false {
            attributes.append(("version", quoted(component.version)))
        }
        if component.cves.isEmpty == false {
            attributes.append(("cves", list(component.cves)))
        }
        if component.holds.isEmpty == false {
            attributes.append(
                ("holds", "[" + component.holds.map(quoted).joined(separator: ", ") + "]")
            )
        }
        if let providedBy = component.providedBy {
            attributes.append(("provided_by", quoted(providedBy)))
        }
        if let source = component.source {
            attributes.append(("source", quoted(source)))
        }
        if component.runsAs != "user" { attributes.append(("runs_as", quoted(component.runsAs))) }
        if component.raisesThreats == false { attributes.append(("threats", "false")) }
        if let shape = component.shape { attributes.append(("shape", quoted(shape))) }
        if component.tags.isEmpty == false {
            attributes.append(("tags", list(component.tags)))
        }
        lines += indent(aligned(attributes))
        for asset in component.assets {
            lines.append("")
            lines.append("  asset \(quoted(asset.name)) {")
            lines.append("    data = \(quoted(asset.data))")
            lines.append("  }")
        }
        lines.append("}")
        return lines
    }

    /// The equals signs of one block line up, which is what makes a diff of one
    /// changed value one changed line.
    private func aligned(_ attributes: [(String, String)]) -> [String] {
        let width = attributes.map(\.0.count).max() ?? 0
        return attributes.map { name, value in
            name + String(repeating: " ", count: width - name.count) + " = " + value
        }
    }

    private func indent(_ lines: [String]) -> [String] {
        lines.map { line in
            if line.hasPrefix(Self.verbatimMark) { return line }
            return line.isEmpty ? "" : "  " + line
        }
    }

    static let verbatimMark = "\u{0}"

    /// A list of texts, the way every list attribute writes.
    private func list(_ values: [String]) -> String {
        "[" + values.map(quoted).joined(separator: ", ") + "]"
    }

    private func quoted(_ text: String) -> String {
        var result = "\""
        for character in text {
            switch character {
            case "\"": result.append("\\\"")
            case "\\": result.append("\\\\")
            case "\n": result.append("\\n")
            case "\t": result.append("\\t")
            default: result.append(character)
            }
        }
        return result + "\""
    }
}
