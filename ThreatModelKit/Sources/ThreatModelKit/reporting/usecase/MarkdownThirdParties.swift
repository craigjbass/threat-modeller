/// The report's Third parties section.
///
/// A vendor review asks who runs a thing, what the team pays for it and what
/// happens when it stops. One row per party answers all three, and names the
/// components it provides and the assets those components hold. A system that
/// names no third party writes no section.
public enum MarkdownThirdParties {
    public static func lines(_ parties: [ReportThirdParty]) -> [String] {
        guard parties.isEmpty == false else { return [] }

        var lines = ["## Third parties", ""]
        lines.append("| Party | Kind | Paying | Uptime | Provides | Assets | Owner |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- |")
        for party in parties {
            let name = party.link.map { "[\(party.name)](\($0))" } ?? party.name
            lines.append(
                "| \(Markdown.cell(name))"
                    + " | \(Markdown.cell(party.kindLabel))"
                    + " | \(party.payingCustomer ? "Yes" : "No")"
                    + " | \(Markdown.cell(party.uptimeLabel))"
                    + " | \(Markdown.cell(list(party.provides)))"
                    + " | \(Markdown.cell(list(party.assetNames)))"
                    + " | \(Markdown.cell(party.owner ?? "\u{2014}"))"
                    + " |"
            )
        }
        lines.append("")

        for party in parties where party.description.isEmpty == false || party.uptimeNotes.isEmpty == false {
            if party.description.isEmpty == false {
                lines.append("- \(party.name): \(party.description)")
            }
            if party.uptimeNotes.isEmpty == false {
                lines.append("  - Uptime: \(party.uptimeNotes)")
            }
        }
        if parties.contains(where: { $0.description.isEmpty == false || $0.uptimeNotes.isEmpty == false }) {
            lines.append("")
        }

        return lines
    }

    private static func list(_ names: [String]) -> String {
        names.isEmpty ? "\u{2014}" : names.joined(separator: ", ")
    }
}
