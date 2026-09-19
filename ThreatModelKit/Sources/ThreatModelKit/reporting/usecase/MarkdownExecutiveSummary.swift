/// The report's Executive summary section.
///
/// This section writes for a reader who reads one page and no more, so its
/// sentences read as a deliverable rather than in the tool's plain register.
/// Every number in it comes from `ReportExecutiveSummary`; this writer counts
/// nothing itself.
public enum MarkdownExecutiveSummary {
    /// `direction` is the one sentence the history states, or nil when
    /// nobody asked for the history.
    public static func lines(
        _ summary: ReportExecutiveSummary,
        components: [ReportComponent],
        connections: [ReportConnection] = [],
        zones: [ReportZone] = [],
        direction: String? = nil
    ) -> [String] {
        var lines = ["## Executive summary", "", summary.verdict, ""]

        if summary.topRisks.isEmpty == false {
            lines.append("**Highest residual risk**")
            lines.append("")
            for (index, threat) in summary.topRisks.enumerated() {
                let level = RiskLevel(rawValue: threat.riskLevel)?.label ?? threat.riskLevel
                lines.append(
                    "\(index + 1). \(threat.name) \u{2014} \(threat.sourceName)"
                        + " \u{2014} \(level) (\(threat.riskScore) of \(ReportMethodology.highestScore))."
                )
                lines += ReportExecutiveSummary.reasons(
                    for: threat,
                    components: components,
                    connections: connections,
                    zones: zones,
                    withNoAction: summary.topRisksWithNoAction
                ).map { "   \($0)" }
            }
            lines.append("")
        }

        if let direction {
            lines.append(direction)
            lines.append("")
        }

        // A model nobody has read again states what a system was, not what it
        // is, so the summary says so.
        if summary.isReviewOverdue {
            lines.append(
                "This model was last read again on \(summary.reviewedOn ?? "an unstated date"), "
                    + "more than \(DocumentControl.reviewIntervalDays) days ago."
            )
            lines.append("")
        }

        if summary.acceptedRisksOverdue > 0 {
            lines.append(
                summary.acceptedRisksOverdue == 1
                    ? "1 accepted risk is past its review date."
                    : "\(summary.acceptedRisksOverdue) accepted risks are past their review date."
            )
            lines.append("")
        }

        if summary.unevidencedControls > 0 {
            lines.append(
                "\(summary.unevidencedControls) of \(summary.implementedControls) implemented "
                    + "controls state no evidence."
            )
            lines.append("")
        }

        if summary.topLeverageActions.isEmpty == false {
            lines.append("**Do first**")
            lines.append("")
            for (index, action) in summary.topLeverageActions.enumerated() {
                lines.append(
                    "\(index + 1). \(action.text) \u{2014} removes \(action.removes)"
                        + " of \(action.totalResidual) residual points"
                )
                let threatWord = action.threatsMoved == 1 ? "threat" : "threats"
                var second = "   across \(action.threatsMoved) \(threatWord);"
                second += action.worstBefore == action.worstAfter
                    ? " worst stays \(action.worstBefore)."
                    : " worst falls \(action.worstBefore) \u{2192} \(action.worstAfter)."
                if let blocker = action.blockedBy {
                    second += " Blocked by \(blocker)."
                }
                lines.append(second)
            }
            lines.append("")
        } else if summary.topActions.isEmpty == false {
            lines.append("**Do first**")
            lines.append("")
            for (index, action) in summary.topActions.enumerated() {
                lines.append(
                    "\(index + 1). \(action.text) \u{2014} answers \(action.threatName)"
                        + " on \(action.sourceName) (\(action.riskScore) of \(ReportMethodology.highestScore))."
                )
            }
            lines.append("")
        }

        lines.append(
            "\(summary.unansweredCount) of \(summary.totalThreats) threats hold"
                + " no answered control and no compensating control."
        )
        lines.append("")

        if summary.exclusionCount > 0 {
            lines.append(
                summary.exclusionCount == 1
                    ? "This model states 1 exclusion, listed under Scope."
                    : "This model states \(summary.exclusionCount) exclusions, listed under Scope."
            )
            lines.append("")
        }

        if summary.adversaryCount > 0 {
            lines.append(
                summary.adversaryCount == 1
                    ? "This model declares 1 adversary, listed under Scope."
                    : "This model declares \(summary.adversaryCount) adversaries, "
                        + "listed under Scope."
            )
            lines.append("")
        }

        if summary.knownExploitedCount > 0 {
            lines.append(
                summary.knownExploitedCount == 1
                    ? "This model holds 1 known exploited CVE, listed under Known vulnerabilities."
                    : "This model holds \(summary.knownExploitedCount) known exploited CVEs, "
                        + "listed under Known vulnerabilities."
            )
            lines.append("")
        }

        if summary.hardDependencyCount > 0 {
            lines.append(
                summary.hardDependencyCount == 1
                    ? "This system stops when 1 third party stops."
                    : "This system stops when any of \(summary.hardDependencyCount) "
                        + "third parties stops."
            )
            lines.append("")
        }

        if summary.openByImpact.isEmpty == false {
            lines.append(
                "Those threats harm "
                    + summary.openByImpact
                        .map { "\($0.label.lowercased()) \($0.count)" }
                        .joined(separator: ", ")
                    + "."
            )
            lines.append("")
        }
        return lines
    }
}
