import ThreatModelKit

/// Writes a library source in the canonical shape.
///
/// The rules are the architecture writer's: two-space indentation, the equals
/// signs of one block lined up, a blank line between blocks, and an attribute
/// holding its default not written. A rewrite of an unchanged source produces
/// no diff.
struct LibraryWriter {
    func write(_ source: LibrarySource) -> String {
        var lines = ["library \(quoted(source.label)) {"]
        var body: [String] = []

        var header: [(String, String)] = []
        if let displayName = source.displayName {
            header.append(("name", quoted(displayName)))
        }
        if let catalogueTag = source.catalogueTag {
            header.append(("catalogue", quoted(catalogueTag)))
        }
        if header.isEmpty == false {
            body += aligned(header)
            body.append("")
        }

        for technology in source.technologies {
            body += technologyBlock(technology)
            body.append("")
        }

        for threat in source.threats {
            body += threatBlock(threat)
            body.append("")
        }

        for mitigation in source.mitigations {
            body.append("mitigation \(quoted(mitigation.id)) {")
            var attributes: [(String, String)] = [("name", quoted(mitigation.name))]
            if mitigation.description.isEmpty == false {
                attributes.append(("description", quoted(mitigation.description)))
            }
            attributes.append(
                ("mitigates", "[" + mitigation.mitigatesThreatIds.map(quoted).joined(separator: ", ") + "]")
            )
            attributes.append(
                ("provided_by", "[" + mitigation.technologyIds.map(quoted).joined(separator: ", ") + "]")
            )
            attributes.append(("reduces_risk_by", String(mitigation.reducesRiskBy)))
            body += indent(aligned(attributes))
            body.append("}")
            body.append("")
        }

        while body.last == "" { body.removeLast() }
        lines += indent(body)
        lines.append("}")
        return lines.joined(separator: "\n") + "\n"
    }

    private func technologyBlock(_ technology: SourceTechnology) -> [String] {
        var lines = ["technology \(quoted(technology.id)) {"]
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
        lines += indent(aligned(attributes))
        lines.append("}")
        return lines
    }

    private func threatBlock(_ threat: SourceLibraryThreat) -> [String] {
        var lines = ["threat \(quoted(threat.id)) {"]
        var body: [String] = []

        var attributes: [(String, String)] = [("name", quoted(threat.name))]
        if threat.description.isEmpty == false {
            attributes.append(("description", quoted(threat.description)))
        }
        attributes.append(("severity", quoted(threat.severityLabel)))
        if threat.strideIds.isEmpty == false {
            attributes.append(
                ("stride", "[" + threat.strideIds.map(quoted).joined(separator: ", ") + "]")
            )
        }
        if threat.isConnectionThreat { attributes.append(("connection", "true")) }
        if threat.isZoneThreat { attributes.append(("zone", "true")) }
        if let zoneContext = threat.zoneContext {
            attributes.append(("zone_context", quoted(zoneContext)))
        }
        if threat.isPathwayThreat { attributes.append(("pathway", "true")) }
        if threat.appliesTo.isEmpty == false {
            attributes.append(
                ("applies_to", "[" + threat.appliesTo.map(quoted).joined(separator: ", ") + "]")
            )
        }
        if let boundary = threat.boundary { attributes.append(("boundary", quoted(boundary))) }
        if threat.runsAs.isEmpty == false {
            attributes.append(
                ("runs_as", "[" + threat.runsAs.map(quoted).joined(separator: ", ") + "]")
            )
        }
        body += aligned(attributes)

        for technique in threat.mitre {
            body.append("")
            body.append("mitre \(quoted(technique.id)) {")
            body += indent(
                aligned([
                    ("name", quoted(technique.name)),
                    ("tactic", quoted(technique.tactic))
                ])
            )
            body.append("}")
        }

        if threat.controlDescriptions.isEmpty == false {
            body.append("")
            for description in threat.controlDescriptions {
                body.append("control \(quoted(description))")
            }
        }

        lines += indent(body)
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
