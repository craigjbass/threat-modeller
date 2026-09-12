public protocol ExportModelAsMarkdownUseCase {
    func execute(_ request: ExportModelAsMarkdownRequest) -> ExportModelAsMarkdownResponse
}

public struct ExportModelAsMarkdownRequest: Equatable, Sendable {
    /// The picture drawn for each of the top residual threats, by file name,
    /// keyed "<threat id>@<source id>".
    ///
    /// A caller that draws none passes none, and the report writes no picture
    /// section. The core cannot draw one itself: drawing depends on the core,
    /// so the core cannot depend on drawing.
    public let threatPictures: [String: String]
    /// The picture drawn for each control, by file name, keyed by the id of
    /// the component the protection comes from.
    public let controlPictures: [String: String]

    public init(
        threatPictures: [String: String] = [:],
        controlPictures: [String: String] = [:]
    ) {
        self.threatPictures = threatPictures
        self.controlPictures = controlPictures
    }
}

public struct ExportModelAsMarkdownResponse: Equatable, Sendable {
    public let markdown: String
    /// What the save panel offers as a name.
    public let fileName: String

    public init(markdown: String, fileName: String) {
        self.markdown = markdown
        self.fileName = fileName
    }
}

/// Writes the report as Markdown, by hand.
///
/// The output is a document a team reviews in a pull request, so its shape is
/// pinned by tests, line for line, the same way the document format is.
public struct ExportModelAsMarkdown: ExportModelAsMarkdownUseCase {
    private let reports: BuildThreatModelReportUseCase

    public init(reports: BuildThreatModelReportUseCase) {
        self.reports = reports
    }

    public func execute(_ request: ExportModelAsMarkdownRequest) -> ExportModelAsMarkdownResponse {
        let report = reports.execute(BuildThreatModelReportRequest()).report
        var lines: [String] = []

        lines.append("# \(report.modelName)")
        lines.append("")
        if let catalogueTag = report.catalogueTag {
            lines.append("Assessed against threat catalogue `\(catalogueTag)`.")
            lines.append("")
        }

        lines += summary(report.summary)
        lines += MarkdownRollups.lines(
            report.rollups,
            showsAssumed: report.assumedMitigations.isEmpty == false
        )
        lines += MarkdownThreatPictures.lines(
            report.rollups.topResidual,
            pictures: request.threatPictures
        )
        lines += components(report.components)
        lines += connections(report.connections)
        lines += zones(report.zones)
        lines += MarkdownAttackPaths.lines(report.attackPaths, notListed: report.attackPathsNotListed)
        lines += MarkdownProtectionDependencies.lines(
            report.protectionDependencies,
            pictures: request.controlPictures
        )
        lines += MarkdownRecommendations.lines(report.recommendations)
        lines += MarkdownAssumptions.lines(
            assumptions: report.assumptions,
            assumedMitigations: report.assumedMitigations
        )
        lines += threats(report.threats)

        return ExportModelAsMarkdownResponse(
            markdown: lines.joined(separator: "\n"),
            fileName: "\(FileNaming.stem(from: report.modelName)).md"
        )
    }

    private func summary(_ summary: ReportSummary) -> [String] {
        var lines = ["## Summary", ""]
        lines.append("- Threats: \(summary.totalThreats)")
        lines.append("- Controls recorded: \(summary.controlsRecorded) of \(summary.controlsOffered)")
        for status in summary.byControlStatus {
            lines.append("- Controls \(status.label.lowercased()): \(status.count)")
        }
        for level in summary.byLevel {
            lines.append("- \(level.label): \(level.count)")
        }
        lines.append("")
        return lines
    }

    private func components(_ components: [ReportComponent]) -> [String] {
        var lines = ["## Components", ""]
        guard components.isEmpty == false else {
            return lines + ["None.", ""]
        }
        lines.append("| Name | Technology | Sensitivity | Privilege | Zone | Assets |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for component in components {
            lines.append(
                "| \(Markdown.cell(component.name))"
                    + " | \(Markdown.cell(component.technologyId))"
                    + " | \(Markdown.cell(component.sensitivityLabel))"
                    + " | \(Markdown.cell(component.privilegeLabel))"
                    + " | \(Markdown.cell(component.zoneName ?? "\u{2014}"))"
                    + " | \(Markdown.cell(component.assetNames.joined(separator: ", ")))"
                    + " |"
            )
        }
        lines.append("")
        return lines
    }

    private func connections(_ connections: [ReportConnection]) -> [String] {
        var lines = ["## Connections", ""]
        guard connections.isEmpty == false else {
            return lines + ["None.", ""]
        }
        for connection in connections {
            var line = "- \(connection.sourceName) \u{2192} \(connection.targetName), by \(connection.kindLabel)"
            if let description = connection.description {
                line += ": \(description)"
            }
            lines.append(line)
        }
        lines.append("")
        return lines
    }

    private func zones(_ zones: [ReportZone]) -> [String] {
        var lines = ["## Zones", ""]
        guard zones.isEmpty == false else {
            return lines + ["None.", ""]
        }
        for zone in zones {
            lines.append("### \(zone.name)")
            lines.append("")
            lines.append("- Network zone: \(zone.networkZoneLabel)")
            lines.append("- Network type: \(zone.networkTypeLabel)")
            lines.append("- Boundary: \(zone.boundaryLabel)")
            if let percent = zone.riskReductionPercent {
                lines.append("- Risk reduction: \(percent)%")
            }
            lines.append(
                "- Holds: "
                    + (zone.componentNames.isEmpty ? "nothing" : zone.componentNames.joined(separator: ", "))
            )
            lines.append("")
        }
        return lines
    }

    private func threats(_ threats: [ReportThreat]) -> [String] {
        var lines = ["## Threats", ""]
        guard threats.isEmpty == false else {
            return lines + ["None.", ""]
        }
        for threat in threats {
            lines.append("### \(threat.name) \u{2014} \(threat.sourceName)")
            lines.append("")
            lines.append(threat.description)
            lines.append("")
            lines.append("- Raised by: \(threat.sourceKind)")
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
            if threat.likelihoodRationale != nil || threat.likelihoodLabel != Likelihood.commodity.label {
                let scoreChanged = threat.scoreBeforeLikelihood != threat.riskScore
                lines.append(
                    "- Likelihood: \(threat.likelihoodLabel)"
                        + (scoreChanged
                            ? " (\(threat.scoreBeforeLikelihood) \u{2192} \(threat.riskScore))"
                            : "")
                )
                if let rationale = threat.likelihoodRationale {
                    lines.append("  - Rationale: \(rationale)")
                }
                lines += Markdown.sourceLines(threat.likelihoodSources)
            }
            if let decision = threat.severityDecision {
                lines.append("- Severity decided: \(decision.fromLabel) \u{2192} \(decision.toLabel)")
                lines.append("  - Rationale: \(decision.rationale)")
                lines += Markdown.sourceLines(decision.sources)
            }
            if threat.scoreIfAssumptionsHold != threat.riskScore {
                lines.append("- If the assumptions hold: \(threat.scoreIfAssumptionsHold)")
            }
            if threat.strideLabels.isEmpty == false {
                lines.append("- STRIDE: \(threat.strideLabels.joined(separator: ", "))")
            }
            if threat.mitreTechniqueIds.isEmpty == false {
                lines.append("- MITRE ATT&CK: \(threat.mitreTechniqueIds.joined(separator: ", "))")
            }
            for compensating in threat.compensating {
                lines.append(
                    "- Compensated by: \(compensating.label)"
                        + " (\(compensating.reducesRiskBy)%,"
                        + " \(threat.scoreBeforeCompensation) \u{2192} \(threat.riskScore))"
                )
                lines.append("  - Rationale: \(compensating.rationale)")
                lines += Markdown.sourceLines(compensating.sources)
            }
            if threat.pathwayMitigationLabels.isEmpty == false {
                lines.append(
                    "- Answered upstream by: "
                        + threat.pathwayMitigationLabels.joined(separator: ", ")
                )
            }
            if threat.mitigatedByComponentLabels.isEmpty == false {
                lines.append(
                    "- Reduced by: "
                        + threat.mitigatedByComponentLabels.joined(separator: ", ")
                )
            }
            if threat.controls.isEmpty == false {
                lines.append("")
                lines.append("Controls:")
                lines.append("")
                for control in threat.controls {
                    lines.append(
                        "- [\(control.isImplemented ? "x" : " ")] \(control.description)"
                            + " \u{2014} \(control.statusLabel)"
                    )
                }
            }
            lines.append("")
        }
        return lines
    }
}

/// Markdown needs one thing escaped in a table, and every render path that
/// lists where a piece of evidence comes from needs one shape for it.
enum Markdown {
    static func cell(_ text: String) -> String {
        text.replacingPipes()
    }

    /// One "  - Source: <value>" line per source, so the likelihood block,
    /// the severity decision, a compensating control and a recommendation
    /// all write their sources the same way. A value starting `http://` or
    /// `https://` renders as a link; any other text renders as it stands.
    static func sourceLines(_ sources: [String]) -> [String] {
        sources.map { source in
            let isLink = source.hasPrefix("http://") || source.hasPrefix("https://")
            return isLink
                ? "  - Source: [\(source)](\(source))"
                : "  - Source: \(source)"
        }
    }
}

extension String {
    func replacingPipes() -> String {
        var result = ""
        for character in self {
            result.append(character == "|" ? "\\" : "")
            result.append(character)
        }
        return result
    }
}

/// Turns a model name into something a file system takes.
public enum FileNaming {
    public static func stem(from modelName: String) -> String {
        let trimmed = modelName.trimmingWhitespace()
        guard trimmed.isEmpty == false else { return "Threat Model" }

        var result = ""
        for character in trimmed {
            switch character {
            case "/", ":", "\\", "\u{0}":
                result.append("-")
            default:
                result.append(character)
            }
        }
        return result
    }
}
