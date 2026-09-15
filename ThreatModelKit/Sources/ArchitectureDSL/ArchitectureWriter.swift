import ThreatModelKit

/// Writes an architecture source in the canonical shape.
///
/// Two-space indentation, attributes aligned on the equals sign inside one
/// block, a blank line between blocks, and the block order technologies, zones,
/// components, flows. A rewrite of an unchanged source produces no diff.
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
            body += indent(aligned(attributes))

            for component in zone.components {
                body.append("")
                body += indent(componentBlock(component))
            }
            body.append("}")
            body.append("")
        }

        for component in source.components {
            body += componentBlock(component)
            body.append("")
        }

        for flow in source.flows {
            if flow.kind == "network" && flow.description == nil {
                body.append("flow \(flow.sourceId) -> \(flow.targetId)")
                continue
            }
            body.append("flow \(flow.sourceId) -> \(flow.targetId) {")
            var attributes: [(String, String)] = [("kind", quoted(flow.kind))]
            if let description = flow.description {
                attributes.append(("description", quoted(description)))
            }
            body += indent(aligned(attributes))
            body.append("}")
            body.append("")
        }
        if source.flows.isEmpty == false && body.last != "" { body.append("") }

        for edge in source.mitigates {
            body.append("mitigates \(edge.sourceId) -> \(edge.targetId) {")
            var attributes: [(String, String)] = [
                ("threats", "[" + edge.threatIds.map(quoted).joined(separator: ", ") + "]"),
                ("reduces_risk_by", String(edge.reducesRiskBy))
            ]
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
        return lines.joined(separator: "\n") + "\n"
    }

    private func componentBlock(_ component: SourceComponent) -> [String] {
        var lines = ["component \(quoted(component.id)) {"]
        var attributes: [(String, String)] = [("technology", quoted(component.technologyId))]
        if let name = component.name { attributes.append(("name", quoted(name))) }
        attributes.append(("data", quoted(component.data)))
        if component.runsAs != "user" { attributes.append(("runs_as", quoted(component.runsAs))) }
        if component.raisesThreats == false { attributes.append(("threats", "false")) }
        if let shape = component.shape { attributes.append(("shape", quoted(shape))) }
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
        lines.map { $0.isEmpty ? "" : "  " + $0 }
    }

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
