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

        lines += MarkdownExecutiveSummary.lines(
            report.executiveSummary,
            components: report.components
        )
        lines += MarkdownRollups.lines(
            report.rollups,
            showsAssumed: report.assumedMitigations.isEmpty == false
        )
        lines += MarkdownThreatPictures.lines(
            report.rollups.topResidual,
            pictures: request.threatPictures
        )
        lines += MarkdownMethodology.lines(report.methodology)
        lines += MarkdownFindings.lines(report.findings, toleranceLabel: report.toleranceLabel)
        lines += MarkdownLeverage.lines(report.actions)
        lines += MarkdownAttackPaths.lines(report.attackPaths, prefix: report.attackPathPrefix)
        lines += MarkdownProtectionDependencies.lines(
            report.protectionDependencies,
            pictures: request.controlPictures
        )
        lines += MarkdownRecommendations.lines(report.recommendations)
        lines += MarkdownAssumptions.lines(
            assumptions: report.assumptions,
            assumedMitigations: report.assumedMitigations
        )
        lines += MarkdownThreatActors.lines(report.threatActors)
        lines += MarkdownGlossary.lines()
        lines += threatRegister(report.threats, summary: report.summary)
        lines += modelInventory(report)
        lines += MarkdownAttackPaths.appendixLines(
            report.attackPathsNotListed,
            beyond: report.attackPathsBeyondAppendix
        )

        return ExportModelAsMarkdownResponse(
            markdown: lines.joined(separator: "\n"),
            fileName: "\(FileNaming.stem(from: report.modelName)).md"
        )
    }

    /// Appendix A: every threat the model raises, in full.
    ///
    /// The control counts the summary bullets used to write open this
    /// appendix, so no number the report published is lost.
    private func threatRegister(_ threats: [ReportThreat], summary: ReportSummary) -> [String] {
        var lines = ["## Appendix A \u{2014} Full threat register", ""]
        lines.append("- Threats: \(summary.totalThreats)")
        lines.append("- Controls recorded: \(summary.controlsRecorded) of \(summary.controlsOffered)")
        for status in summary.byControlStatus {
            lines.append("- Controls \(status.label.lowercased()): \(status.count)")
        }
        for level in summary.byLevel {
            lines.append("- \(level.label): \(level.count)")
        }
        lines.append("")

        guard threats.isEmpty == false else {
            return lines + ["None.", ""]
        }
        for threat in threats {
            lines += MarkdownThreatStanza.lines(threat)
        }
        return lines
    }

    /// Appendix B: what the model holds.
    private func modelInventory(_ report: Report) -> [String] {
        ["## Appendix B \u{2014} Model inventory", ""]
            + components(report.components)
            + connections(report.connections)
            + zones(report.zones)
    }

    private func components(_ components: [ReportComponent]) -> [String] {
        var lines = ["### Components", ""]
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
        var lines = ["### Connections", ""]
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
        var lines = ["### Zones", ""]
        guard zones.isEmpty == false else {
            return lines + ["None.", ""]
        }
        for zone in zones {
            lines.append("#### \(zone.name)")
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
