/// The report's Scope section.
///
/// A reader must be able to tell a flow that was modelled and found safe from
/// a flow nobody modelled. The use cases say what the model covers, the users
/// say who uses it, the adversaries say who the model does not trust, and the
/// exclusions say what it leaves out and why.
public enum MarkdownScope {
    public static func lines(
        useCases: [ReportUseCase],
        exclusions: [ReportExclusion],
        users: [ReportUser] = []
    ) -> [String] {
        guard useCases.isEmpty == false || exclusions.isEmpty == false || users.isEmpty == false
        else { return [] }

        var lines = ["## Scope", ""]

        if useCases.isEmpty == false {
            lines.append("### Use cases")
            lines.append("")
            for useCase in useCases {
                lines.append("- \(useCase.label): \(useCase.text)")
            }
            lines.append("")
        }

        let legitimate = users.filter { $0.isAdversary == false }
        if legitimate.isEmpty == false {
            lines.append("### Users")
            lines.append("")
            for user in legitimate {
                lines.append("- " + line(for: user))
            }
            lines.append("")
        }

        let adversaries = users.filter(\.isAdversary)
        if adversaries.isEmpty == false {
            lines.append("### Adversaries")
            lines.append("")
            for adversary in adversaries {
                lines.append("- " + line(for: adversary))
            }
            lines.append("")
        }

        if exclusions.isEmpty == false {
            lines.append("### Exclusions")
            lines.append("")
            for exclusion in exclusions {
                lines.append("- \(exclusion.label): \(exclusion.text)")
                lines.append("  - Rationale: \(exclusion.rationale)")
            }
            lines.append("")
        }

        return lines
    }

    /// One user on one line.
    public static func line(for user: ReportUser) -> String {
        var words: [String] = []
        if user.isAdversary { words.append("adversary") }
        if user.role.isEmpty == false { words.append(user.role) }
        words.append(user.accessLabel)
        let facts = words.joined(separator: ", ")
        var clauses: [String] = []
        if user.reaches.isEmpty == false || user.clients.isEmpty {
            clauses.append("reaches \(joined(user.reaches))")
        }
        for client in user.clients {
            clauses.append("through \(client.name) reaches \(joined(client.reaches))")
        }
        if let clearance = user.clearanceName {
            clauses.append("holds the clearance \(clearance)")
        }
        if let actor = user.threatActorName {
            clauses.append("is the threat actor \(actor)")
        }
        return "\(user.name) (\(facts)): " + clauses.joined(separator: "; ")
    }

    /// `nothing`, `A`, `A and B`, or `A, B and C`.
    private static func joined(_ names: [String]) -> String {
        switch names.count {
        case 0: return "nothing"
        case 1: return names[0]
        default:
            return names.dropLast().joined(separator: ", ") + " and " + names[names.count - 1]
        }
    }
}
