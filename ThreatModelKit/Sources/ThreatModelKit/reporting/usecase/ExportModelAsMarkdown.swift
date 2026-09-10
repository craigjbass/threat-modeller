public protocol ExportModelAsMarkdownUseCase {
    func execute(_ request: ExportModelAsMarkdownRequest) -> ExportModelAsMarkdownResponse
}

public struct ExportModelAsMarkdownRequest: Equatable, Sendable {
    public init() {}
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
        lines += MarkdownRollups.lines(report.rollups)
        lines += components(report.components)
        lines += connections(report.connections)
        lines += zones(report.zones)
        lines += MarkdownAttackPaths.lines(report.attackPaths, notListed: report.attackPathsNotListed)
        lines += MarkdownProtectionDependencies.lines(report.protectionDependencies)
        lines += MarkdownRecommendations.lines(report.recommendations)
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
        lines.append("| Name | Technology | Sensitivity | Zone | Assets |")
        lines.append("| --- | --- | --- | --- | --- |")
        for component in components {
            lines.append(
                "| \(Markdown.cell(component.name))"
                    + " | \(Markdown.cell(component.technologyId))"
                    + " | \(Markdown.cell(component.sensitivityLabel))"
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
            lines.append("- \(connection.sourceName) \u{2192} \(connection.targetName)")
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
            }
            if threat.pathwayMitigationLabels.isEmpty == false {
                lines.append(
                    "- Answered upstream by: "
                        + threat.pathwayMitigationLabels.joined(separator: ", ")
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

/// Markdown needs one thing escaped in a table, and this is it.
enum Markdown {
    static func cell(_ text: String) -> String {
        text.replacingPipes()
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
