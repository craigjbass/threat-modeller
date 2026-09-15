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
    /// The diagram of each top residual threat, as text a wiki renders, keyed
    /// the way `threatPictures` is keyed. A threat that states one writes the
    /// diagram itself rather than a link to an image file.
    public let threatDiagrams: [String: String]
    /// The diagram of each control, as text, by the control's protector id.
    public let controlDiagrams: [String: String]
    /// The team's own shape for the report, or nil for the shape this
    /// application ships.
    public let template: ReportTemplate?
    /// The file the caller wrote the risk-over-time graph to, relative to the
    /// report, or nil when it drew none.
    public let riskOverTimePicture: String?
    /// What the model scored at each sampled commit, and what changed since
    /// the newest one. Empty when nobody asked for the history.
    public let history: [RiskHistoryRow]
    public let historyTruncated: Bool
    public let change: RiskChange?

    public init(
        threatPictures: [String: String] = [:],
        controlPictures: [String: String] = [:],
        threatDiagrams: [String: String] = [:],
        controlDiagrams: [String: String] = [:],
        template: ReportTemplate? = nil,
        riskOverTimePicture: String? = nil,
        history: [RiskHistoryRow] = [],
        historyTruncated: Bool = false,
        change: RiskChange? = nil
    ) {
        self.threatPictures = threatPictures
        self.controlPictures = controlPictures
        self.threatDiagrams = threatDiagrams
        self.controlDiagrams = controlDiagrams
        self.template = template
        self.riskOverTimePicture = riskOverTimePicture
        self.history = history
        self.historyTruncated = historyTruncated
        self.change = change
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

    /// The shape this application ships: every section, in the order the
    /// report has always written them, and nothing of a team's own. A project
    /// that names no template renders through this, and the bytes are the
    /// bytes the writer produced before templates existed.
    public static let defaultTemplate = ReportTemplate(
        pieces: ReportTemplate.Slot.allCases.sorted { left, right in
            (defaultOrder.firstIndex(of: left) ?? 0) < (defaultOrder.firstIndex(of: right) ?? 0)
        }.map { ReportTemplate.Piece.slot($0) }
    )

    /// The order the report has always written its sections in.
    static let defaultOrder: [ReportTemplate.Slot] = [
        .systemName,
        .catalogueTag,
        .documentControl,
        .executiveSummary,
        .scope,
        .dataInventory,
        .thirdParties,
        .policy,
        .riskOverTime,
        .whatChanged,
        .rollups,
        .threatPictures,
        .methodology,
        .findings,
        .leverage,
        .attackPaths,
        .attackTrees,
        .protectionDependencies,
        .recommendations,
        .acceptedRisks,
        .assumptions,
        .threatActors,
        .glossary,
        .threatRegister,
        .modelInventory,
        .diagrams,
        .attackPathsAppendix
    ]

    public func execute(_ request: ExportModelAsMarkdownRequest) -> ExportModelAsMarkdownResponse {
        let report = reports.execute(
            BuildThreatModelReportRequest(
                history: request.history,
                historyTruncated: request.historyTruncated,
                change: request.change
            )
        ).report

        // Every section, written once, and the template decides which of them
        // a reader sees and in what order. A template naming none of them is
        // a template that writes only the team's own words.
        var sections: [ReportTemplate.Slot: [String]] = [:]
        sections[.systemName] = ["# \(report.modelName)", ""]
        sections[.catalogueTag] = report.catalogueTag.map {
            ["Assessed against threat catalogue `\($0)`.", ""]
        } ?? []
        sections[.documentControl] = MarkdownDocumentControl.lines(report.documentControl)
        sections[.executiveSummary] = MarkdownExecutiveSummary.lines(
            report.executiveSummary,
            components: report.components,
            direction: report.change?.direction
        )
        sections[.scope] = MarkdownScope.lines(
            useCases: report.useCases,
            exclusions: report.exclusions
        )
        sections[.dataInventory] = MarkdownDataInventory.lines(report.dataInventory)
        sections[.thirdParties] = MarkdownThirdParties.lines(report.thirdParties)
        sections[.policy] = MarkdownPolicy.lines(report.policy)
        sections[.riskOverTime] = MarkdownRiskOverTime.lines(
            report.history,
            picturePath: request.riskOverTimePicture,
            truncated: report.historyTruncated
        )
        sections[.whatChanged] = MarkdownWhatChanged.lines(
            report.change,
            since: report.history.first?.commit
        )
        sections[.rollups] = MarkdownRollups.lines(
            report.rollups,
            showsAssumed: report.assumedMitigations.isEmpty == false
        )
        sections[.threatPictures] = MarkdownThreatPictures.lines(
            report.rollups.topResidual,
            pictures: request.threatPictures,
            diagrams: request.threatDiagrams
        )
        sections[.methodology] = MarkdownMethodology.lines(report.methodology)
        sections[.findings] = MarkdownFindings.lines(
            report.findings,
            toleranceLabel: report.toleranceLabel
        )
        sections[.leverage] = MarkdownLeverage.lines(report.actions)
        sections[.attackPaths] = MarkdownAttackPaths.lines(
            report.attackPaths,
            prefix: report.attackPathPrefix
        )
        sections[.attackTrees] = MarkdownAttackTrees.lines(
            report.attackTrees,
            routes: report.attackPathCount
        )
        sections[.protectionDependencies] = MarkdownProtectionDependencies.lines(
            report.protectionDependencies,
            pictures: request.controlPictures,
            diagrams: request.controlDiagrams
        )
        sections[.recommendations] = MarkdownRecommendations.lines(report.recommendations)
        sections[.acceptedRisks] = MarkdownAcceptedRisks.lines(report.acceptedRisks)
        sections[.assumptions] = MarkdownAssumptions.lines(
            assumptions: report.assumptions,
            assumedMitigations: report.assumedMitigations
        )
        sections[.threatActors] = MarkdownThreatActors.lines(report.threatActors)
        sections[.glossary] = MarkdownGlossary.lines()
        sections[.threatRegister] = threatRegister(report.threats, summary: report.summary)
        sections[.modelInventory] = modelInventory(report)
        sections[.diagrams] = MarkdownDiagrams.lines(report.diagrams)
        sections[.attackPathsAppendix] = MarkdownAttackPaths.appendixLines(
            report.attackPathsNotListed,
            beyond: report.attackPathsBeyondAppendix
        )

        let template = request.template ?? Self.defaultTemplate
        var lines: [String] = []
        if let banner = template.frontMatter.banner {
            lines.append("> \(banner)")
            lines.append("")
        }
        for piece in template.pieces {
            switch piece {
            case .text(let text): lines.append(text)
            case .slot(let slot): lines += sections[slot] ?? []
            }
        }

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
    /// A fenced block, in the language named. The text keeps every line as
    /// it stands, so a diagram a reader edits reads back the way they wrote
    /// it.
    static func fenced(_ text: String, as language: String) -> [String] {
        var lines = ["```\(language)"]
        lines += text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        if text.hasSuffix("\n") { lines.removeLast() }
        lines.append("```")
        return lines
    }

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
