import ThreatModelKit

/// Writes a governance source in the canonical shape.
///
/// The rules are the controls writer's: two-space indentation, the equals
/// signs of one block lined up, a blank line between blocks, and an attribute
/// holding its default not written. A rewrite of an unchanged source produces
/// no diff.
struct GovernanceWriter {
    func write(_ source: GovernanceSource) -> String {
        var lines = ["governance for \(quoted(source.systemName)) {"]
        var body: [String] = []

        for threat in source.threats {
            body += threatBlock(threat)
            body.append("")
        }

        for action in source.actions {
            body += workBlock(action, keyword: "action")
            body.append("")
        }

        while body.last == "" { body.removeLast() }
        lines += indent(body)
        lines.append("}")
        return lines.joined(separator: "\n") + "\n"
    }

    private func threatBlock(_ threat: SourceGovernedThreat) -> [String] {
        let header = "threat \(quoted(threat.threatId))"
            + " on \(threat.sourceKind) \(quoted(threat.sourceId)) {"
        var lines = [threat.isStale ? "stale " + header : header]
        var body: [String] = []

        for accepted in threat.accepted {
            body += acceptedBlock(accepted)
            body.append("")
        }
        for work in threat.work {
            body += workBlock(work, keyword: "work")
            body.append("")
        }

        while body.last == "" { body.removeLast() }
        lines += indent(body)
        lines.append("}")
        return lines
    }

    private func acceptedBlock(_ accepted: SourceAcceptedRisk) -> [String] {
        let header = "accepted \(quoted(accepted.control)) {"
        var lines = [accepted.isStale ? "stale " + header : header]

        var attributes: [(String, String)] = []
        if accepted.owner.isEmpty == false { attributes.append(("owner", quoted(accepted.owner))) }
        if let acceptedOn = accepted.acceptedOn {
            attributes.append(("accepted_on", quoted(acceptedOn)))
        }
        if let reviewBy = accepted.reviewBy { attributes.append(("review_by", quoted(reviewBy))) }
        if accepted.rationale.isEmpty == false {
            attributes.append(("rationale", quoted(accepted.rationale)))
        }
        if accepted.sources.isEmpty == false {
            attributes.append(
                ("sources", "[" + accepted.sources.map(quoted).joined(separator: ", ") + "]")
            )
        }

        lines += indent(aligned(attributes))
        lines.append("}")
        return lines
    }

    private func workBlock(_ work: SourcePlannedWork, keyword: String) -> [String] {
        let header = "\(keyword) \(quoted(work.label)) {"
        var lines = [work.isStale ? "stale " + header : header]

        var attributes: [(String, String)] = []
        if work.owner.isEmpty == false { attributes.append(("owner", quoted(work.owner))) }
        if let effort = work.effort { attributes.append(("effort", quoted(effort))) }
        if let dueBy = work.dueBy { attributes.append(("due_by", quoted(dueBy))) }
        if work.status != SourcePlannedWork.defaultStatus {
            attributes.append(("status", quoted(work.status)))
        }
        if work.acceptance.isEmpty == false {
            attributes.append(("acceptance", quoted(work.acceptance)))
        }
        if work.note.isEmpty == false { attributes.append(("note", quoted(work.note))) }
        if work.sources.isEmpty == false {
            attributes.append(
                ("sources", "[" + work.sources.map(quoted).joined(separator: ", ") + "]")
            )
        }

        lines += indent(aligned(attributes))
        lines.append("}")
        return lines
    }

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
