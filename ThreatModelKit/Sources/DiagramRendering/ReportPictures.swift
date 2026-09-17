import Foundation
import ThreatModelKit

/// Every picture a report holds, drawn once.
///
/// The window and the executable both write the report, and a reader compares
/// the two files. One type draws the set, so neither caller can draw a
/// different one.
///
/// The design is
/// `docs/superpowers/specs/2026-09-17-report-stage-pictures-design.md`.
public struct ReportPictures: Equatable, Sendable {
    /// The file each top residual threat's picture is linked under, keyed
    /// "<threat id>@<source id>".
    public let threatPictures: [String: String]
    /// The file each control's picture is linked under, by the id of the
    /// component the protection comes from.
    public let controlPictures: [String: String]
    /// What each of those file names draws, as SVG. A page inlines these, and
    /// a Markdown report writes them beside itself.
    public let sources: [String: String]
    /// The whole system as SVG, written under the title.
    public let wholePicture: String
    /// The risk-over-time graph as SVG, or nil when the history draws none.
    public let riskOverTimeChart: String?
    /// The file the report links that graph under, or nil.
    public let riskOverTimePicture: String?

    public init(
        threatPictures: [String: String],
        controlPictures: [String: String],
        sources: [String: String],
        wholePicture: String,
        riskOverTimeChart: String?,
        riskOverTimePicture: String?
    ) {
        self.threatPictures = threatPictures
        self.controlPictures = controlPictures
        self.sources = sources
        self.wholePicture = wholePicture
        self.riskOverTimeChart = riskOverTimeChart
        self.riskOverTimePicture = riskOverTimePicture
    }

    /// The set a report of this model holds.
    ///
    /// `stem` names the files, so the same report always names the same file.
    /// `history` draws the risk-over-time graph, and an empty history draws
    /// none.
    public static func of(
        model: DiagramBuilder.Model,
        report: Report,
        stem: String,
        history: [RiskHistoryRow] = []
    ) -> ReportPictures {
        let threats = ThreatDiagrams.pictures(
            of: model,
            for: report.rollups.topResidual,
            stem: stem
        )
        let controls = ThreatDiagrams.controlPictures(
            of: model,
            for: report.protectionDependencies,
            stem: stem
        )

        var sources: [String: String] = [:]
        for picture in threats { sources[picture.fileName] = picture.svg }
        for picture in controls { sources[picture.fileName] = picture.svg }

        let chart = RiskOverTimeChart.svg(of: history)
        let chartFileName = chart.isEmpty ? nil : "\(stem)-risk-over-time.svg"
        if let chartFileName { sources[chartFileName] = chart }

        return ReportPictures(
            threatPictures: Dictionary(
                uniqueKeysWithValues: threats.map { ($0.key, $0.fileName) }
            ),
            controlPictures: Dictionary(
                uniqueKeysWithValues: controls.map { ($0.protectorId, $0.fileName) }
            ),
            sources: sources,
            wholePicture: SvgWriter.svg(of: DiagramBuilder.drawing(of: model)),
            riskOverTimeChart: chart.isEmpty ? nil : chart,
            riskOverTimePicture: chartFileName
        )
    }

    /// The files a Markdown report needs beside it: every picture the report
    /// links, by the path the link states.
    public var files: [String: String] { sources }
}
