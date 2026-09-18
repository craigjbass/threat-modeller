/// The report's Scope section.
///
/// A reader must be able to tell a flow that was modelled and found safe from
/// a flow nobody modelled. The use cases say what the model covers, the users
/// say who uses it, and the exclusions say what it leaves out and why. A
/// system that states none of the three writes no section, so a reader never
/// meets an empty heading.
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

        if users.isEmpty == false {
            lines.append("### Users")
            lines.append("")
            for user in users {
                lines.append("- " + line(for: user))
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

    /// One user on one line: the name, the role and the access in brackets,
    /// what the user reaches, each client the user holds with what it
    /// reaches, and the actor the user is. A user that reaches nothing and
    /// holds nothing reads `reaches nothing`.
    public static func line(for user: ReportUser) -> String {
        let facts = user.role.isEmpty
            ? user.accessLabel
            : "\(user.role), \(user.accessLabel)"
        var clauses: [String] = []
        if user.reaches.isEmpty == false || user.clients.isEmpty {
            clauses.append("reaches \(joined(user.reaches))")
        }
        for client in user.clients {
            clauses.append("through \(client.name) reaches \(joined(client.reaches))")
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
