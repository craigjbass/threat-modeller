import Foundation

/// The report's Risk over time and What changed sections.
///
/// A project with one commit writes neither: there is nothing to compare.
public enum MarkdownRiskOverTime {
    /// `picturePath` is the file the caller wrote the graph to, relative to
    /// the report. Nil writes the rows and no picture.
    public static func lines(
        _ rows: [RiskHistoryRow],
        picturePath: String? = nil,
        truncated: Bool = false
    ) -> [String] {
        guard rows.count >= 2 else { return [] }

        var lines = ["## Risk over time", ""]
        if let picturePath {
            lines.append("![Total residual risk at each sampled commit](\(picturePath))")
            lines.append("")
        }
        lines.append("| Date | Commit | Author | Total | Worst | Threats | Accepted | Open trees | Catalogue |")
        lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")

        for row in rows {
            guard let numbers = row.numbers else {
                lines.append(
                    "| \(day(row.commit.date)) | \(row.commit.shortHash)"
                        + " | \(Markdown.cell(row.commit.author)) | did not parse | | | | | |"
                )
                continue
            }
            lines.append(
                "| \(day(row.commit.date)) | \(row.commit.shortHash)"
                    + " | \(Markdown.cell(row.commit.author)) | \(numbers.totalScore)"
                    + " | \(numbers.worstScore) | \(numbers.threatCount)"
                    + " | \(numbers.acceptedRisks) | \(numbers.openAttackTrees)"
                    + " | \(numbers.catalogueTag ?? "\u{2014}") |"
            )
        }
        lines.append("")

        if truncated {
            lines.append(
                "This is the newest \(rows.count) commits that touched a threat model file. "
                    + "The project holds more."
            )
            lines.append("")
        }
        return lines
    }

    /// The day a commit was made, written `YYYY-MM-DD` in UTC, so two runs on
    /// two machines write the same rows.
    public static func day(_ date: Date) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? .gmt
        let parts = calendar.dateComponents([.year, .month, .day], from: date)
        return GovernanceDate(
            year: parts.year ?? 1970,
            month: parts.month ?? 1,
            day: parts.day ?? 1
        )?.description ?? "1970-01-01"
    }
}

/// The report's What changed section.
public enum MarkdownWhatChanged {
    public static func lines(_ change: RiskChange?, since commit: SourceCommit?) -> [String] {
        guard let change, let commit, change.isEmpty == false else { return [] }

        var lines = ["## What changed", ""]
        lines.append(
            "Since \(commit.shortHash) on \(MarkdownRiskOverTime.day(commit.date)). "
                + change.direction
        )
        lines.append("")

        if let catalogueMoved = change.catalogueMoved {
            // A score that moved on a catalogue change is not a posture
            // change, so the reader is told before they read the numbers.
            lines.append("**\(catalogueMoved).** A score that moved with it is not a posture change.")
            lines.append("")
        }

        lines += list("Threats raised", change.raised)
        lines += list("Threats no longer raised", change.gone)
        lines += list("Controls whose status changed", change.controlsChanged)
        lines += list("Risks newly accepted", change.acceptedAdded)
        lines += list("Review dates moved", change.reviewDatesMoved)

        if change.scoreDeltas.isEmpty == false {
            lines.append("**Score by element**")
            lines.append("")
            lines.append("| Element | Then | Now | Change |")
            lines.append("| --- | --- | --- | --- |")
            for delta in change.scoreDeltas {
                let sign = delta.delta > 0 ? "+" : ""
                lines.append(
                    "| \(Markdown.cell(delta.name)) | \(delta.then) | \(delta.now)"
                        + " | \(sign)\(delta.delta) |"
                )
            }
            lines.append("")
        }
        return lines
    }

    private static func list(_ heading: String, _ items: [String]) -> [String] {
        guard items.isEmpty == false else { return [] }
        var lines = ["**\(heading)**", ""]
        lines += items.map { "- \(Markdown.cell($0))" }
        lines.append("")
        return lines
    }
}
