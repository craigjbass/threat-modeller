/// One threat, written the same way wherever the report writes it.
///
/// The findings section and the threat register both write this, so a threat
/// a reader finds in one reads the same in the other.
public enum MarkdownThreatStanza {
    public static func lines(_ threat: ReportThreat) -> [String] {
        var lines: [String] = []
        lines.append("### \(threat.name) \u{2014} \(threat.sourceName)")
        lines.append("")
        lines.append(threat.description)
        lines.append("")
        lines.append("- Raised by: \(threat.sourceKind)")
        if let matchReason = threat.matchReason {
            lines.append("- Narrowed to this element: \(matchReason)")
        }
        lines.append("- Severity: \(threat.severityLabel)")
        if threat.inherentScore == threat.riskScore {
            lines.append("- Risk: \(threat.riskLevel) (\(threat.riskScore))")
        } else {
            lines.append(
                "- Risk: \(threat.riskLevel) (\(threat.riskScore)),"
                    + " before controls \(threat.inherentScore)"
            )
        }
        // A finding is worth printing even when the stage floored at 1
        // both before and after: the tier, the rationale and the
        // sources are the evidence this block exists to publish, and a
        // threat that already scored 1 must not hide them.
        // A known exploited CVE names itself even at commodity: the reader
        // must see what set the tier.
        if threat.likelihoodRationale != nil || threat.likelihoodLabel != Likelihood.commodity.label
            || threat.likelihoodReason.hasSuffix(LikelihoodSource.knownExploitedSuffix) {
            let scoreChanged = threat.scoreBeforeLikelihood != threat.riskScore
            // A finding writes its own rationale on the next line, so naming
            // the finding here would say the same thing twice.
            let reason = threat.likelihoodRationale == nil ? ", \(threat.likelihoodReason)" : ""
            lines.append(
                "- Likelihood: \(threat.likelihoodLabel)\(reason)"
                    + (scoreChanged
                        ? " (\(threat.scoreBeforeLikelihood) \u{2192} \(threat.riskScore))"
                        : "")
            )
            if let rationale = threat.likelihoodRationale {
                if let findingLabel = threat.likelihoodFindingLabel {
                    lines.append("  - Finding: \(findingLabel)")
                }
                lines.append("  - Rationale: \(rationale)")
            }
            lines += Markdown.sourceLines(threat.likelihoodSources)
        }
        if let decision = threat.severityDecision {
            lines.append("- Severity decided: \(decision.fromLabel) \u{2192} \(decision.toLabel)")
            lines.append("  - Rationale: \(decision.rationale)")
            lines += Markdown.sourceLines(decision.sources)
        }
        if let scoreBeforeTree = threat.scoreBeforeTree {
            lines.append("- Before the attack tree: \(scoreBeforeTree)")
        }
        if let raisedByTree = threat.raisedByTree {
            lines.append("- Raised by the tree: \(raisedByTree)")
        }
        if threat.scoreIfAssumptionsHold != threat.riskScore {
            lines.append("- If the proposed are in place: \(threat.scoreIfAssumptionsHold)")
        }
        if threat.assetsAtRisk.isEmpty == false {
            lines.append("- Assets at risk: \(threat.assetsAtRisk.joined(separator: ", "))")
        }
        if threat.impactLabels.isEmpty == false {
            lines.append("- Impact: \(threat.impactLabels.joined(separator: ", "))")
        }
        if threat.strideLabels.isEmpty == false {
            lines.append("- STRIDE: \(threat.strideLabels.joined(separator: ", "))")
        }
        if let overriddenBy = threat.overriddenBy {
            let changes = threat.overrideChanges.isEmpty
                ? ""
                : " (\(threat.overrideChanges.joined(separator: ", ")))"
            lines.append("- Changed by the library: \(overriddenBy)\(changes)")
        }
        if threat.mitreTechniqueIds.isEmpty == false {
            // Each id is a link, so the Markdown and the page built from it
            // both take a reader to the technique.
            let linked = threat.mitreTechniqueIds.map { id -> String in
                let link = "[\(id)](\(MitreLink.address(of: id)))"
                // The name comes from the ATT&CK data on this machine. A
                // machine that has not synchronised prints the bare id.
                guard let said = threat.mitreTechniqueNames[id] else { return link }
                return "\(link) \(said)"
            }
            lines.append("- MITRE ATT&CK: \(linked.joined(separator: ", "))")
        }
        if threat.performedByLabels.isEmpty == false {
            lines.append("- Performed by: \(threat.performedByLabels.joined(separator: ", "))")
        }
        for compensating in threat.compensating {
            lines.append(
                "- Compensated by: \(compensating.label)"
                    + " (\(compensating.reducesRiskBy)%,"
                    + " \(threat.scoreBeforeCompensation) \u{2192} \(threat.riskScore))"
                    + (compensating.evidence.map { ", \($0)" } ?? "")
            )
            lines.append("  - Rationale: \(compensating.rationale)")
            lines += Markdown.sourceLines(compensating.sources)
        }
        if threat.pathwayMitigationLabels.isEmpty == false {
            let described = threat.pathwayMitigationLabels.map { label -> String in
                guard let mode = threat.pathwayMitigationModes[label] else { return label }
                return "\(label) (\(mode))"
            }
            lines.append("- Answered upstream by: " + described.joined(separator: ", "))
        }
        if threat.mitigatedByComponentLabels.isEmpty == false {
            let named = threat.mitigatedByComponentLabels.enumerated().map { index, label -> String in
                guard index < threat.mitigatedByComponentReductions.count else { return label }
                return "\(label) (\(threat.mitigatedByComponentReductions[index])%)"
            }
            lines.append("- Reduced by: " + named.joined(separator: ", "))
        }
        if threat.controls.isEmpty == false {
            lines.append("")
            lines.append("Controls:")
            lines.append("")
            for control in threat.controls {
                lines.append(
                    "- [\(control.isImplemented ? "x" : " ")] \(control.description)"
                        + " \u{2014} \(control.statusLabel)"
                        + (control.mitigatedBy.isEmpty
                            ? ""
                            : " \u{2014} mitigated by "
                                + control.mitigatedBy.joined(separator: ", "))
                        + (control.evidence.map { " \u{2014} \($0)" } ?? "")
                        + (control.note.map { " \u{2014} \($0)" } ?? "")
                )
            }
        }
        lines.append("")
        return lines
    }
}
