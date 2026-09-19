import ThreatModelKit

/// What the diagram says when a person rests the pointer on it.
///
/// A node is a name, a shape and a number. Nothing said what the number
/// counted, what the technology was, or which zone held the node. This states
/// each of those in one place, so a test reads the words.
nonisolated enum HoverText {
    /// What hovering a node says: what it is, where it sits, and how much is
    /// open on it.
    static func node(
        _ component: ViewedComponent,
        zoneName: String?,
        risk: ElementRisk?,
        clientNames: [String] = []
    ) -> String {
        var lines = [
            component.isUser ? userLine(component, clientNames: clientNames) : component.technologyId
        ]
        lines.append(zoneName.map { "In \($0)" } ?? "In no zone")
        lines.append(openCount(risk))
        return lines.joined(separator: "\n")
    }

    /// What a user is: a user, the role when one is stated, the actor when
    /// the user is one, and the clients the user holds.
    private static func userLine(_ component: ViewedComponent, clientNames: [String]) -> String {
        var text = component.role.isEmpty ? "User" : "User, \(component.role)"
        if let actorId = component.threatActorId {
            text += ", the threat actor \(actorId)"
        }
        switch clientNames.count {
        case 0: break
        case 1: text += ", through \(clientNames[0])"
        default:
            text += ", through " + clientNames.dropLast().joined(separator: ", ")
                + " and \(clientNames[clientNames.count - 1])"
        }
        return text
    }

    /// What hovering a badge says: the three worst open threats, and how many
    /// more there are.
    static func badge(_ risk: ElementRisk?) -> String {
        guard let risk, risk.openCount > 0 else { return "Nothing open" }

        var lines = risk.worstOpen.map { "\($0.name) — \($0.score)" }
        let more = risk.openCount - risk.worstOpen.count
        if more > 0 {
            lines.append(more == 1 ? "and 1 more" : "and \(more) more")
        }
        return lines.joined(separator: "\n")
    }

    /// What hovering a zone says: what kind of zone it is, and how much is
    /// open on it.
    static func zone(_ zone: ViewedZone, risk: ElementRisk?) -> String {
        var lines = ["\(zone.networkZoneId) zone"]
        if zone.riskReductionEnabled {
            lines.append("Lowers risk by \(zone.riskReductionPercent)%")
        }
        lines.append(openCount(risk))
        return lines.joined(separator: "\n")
    }

    private static func openCount(_ risk: ElementRisk?) -> String {
        let open = risk?.openCount ?? 0
        let total = risk?.totalCount ?? 0
        if total == 0 { return "No threats" }
        return open == 1 ? "1 open threat of \(total)" : "\(open) open threats of \(total)"
    }
}
