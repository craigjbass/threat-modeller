import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// Given a threat model worth reporting
/// When I export it as one page
/// Then the page says what the Markdown says, holds the pictures it was given,
/// and needs nothing beside it
struct ExportingAReportAsOnePageTests {
    private let app = TestDependencies()

    private func aModelWorthReporting() {
        _ = app.renameThreatModel().execute(RenameThreatModelRequest(name: "Payments"))
        guard case .added(let source) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "restricted")
        ), case .added(let target) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 400, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the components were not added")
            return
        }
        _ = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: source, targetComponentId: target)
        )
        _ = app.addZone().execute(AddZoneRequest(x: -100, y: -100, width: 900, height: 700))
    }

    @Test func writesThePageTheReportNames() {
        aModelWorthReporting()

        let page = app.exportModelAsHtml().execute(ExportModelAsHtmlRequest())
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest())

        #expect(page.fileName == markdown.fileName.replacingOccurrences(of: ".md", with: ".html"))
        #expect(page.html.hasPrefix("<!doctype html>"))
        #expect(page.html.contains("<title>Payments</title>"))
        #expect(page.html.contains("<h1>Payments</h1>"))
    }

    @Test func writesEverySectionTheMarkdownWrites() {
        aModelWorthReporting()

        let page = app.exportModelAsHtml().execute(ExportModelAsHtmlRequest())
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest())
        let headings = markdown.markdown
            .split(separator: "\n", omittingEmptySubsequences: false)
            .filter { $0.hasPrefix("## ") }
            .map { String($0.dropFirst(3)) }

        #expect(headings.isEmpty == false)
        for heading in headings {
            // Every heading the report writes is plain text, so the page
            // carries it as it stands.
            #expect(page.html.contains("<h2>\(heading)</h2>"))
        }
    }

    @Test func leavesNoLineOfTheReportUnconverted() {
        aModelWorthReporting()

        let page = app.exportModelAsHtml().execute(ExportModelAsHtmlRequest())
        let body = page.html
            .split(separator: "\n", omittingEmptySubsequences: false)
            .drop { $0.contains("<body>") == false }

        // A construct the converter does not know falls through as a
        // paragraph, and its markers show. Nothing in the report may.
        for line in body where line.hasPrefix("<p>") {
            #expect(line.hasPrefix("<p>|") == false)
            #expect(line.hasPrefix("<p>- ") == false)
            #expect(line.hasPrefix("<p>#") == false)
            #expect(line.hasPrefix("<p>![") == false)
        }
    }

    @Test func holdsThePicturesItWasGivenAndNeedsNoFileBesideIt() {
        aModelWorthReporting()
        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
        guard let first = report.rollups.topResidual.first else {
            Issue.record("the model raised no threat to picture")
            return
        }
        let key = MarkdownThreatPictures.key(threatId: first.threatId, sourceId: first.sourceId)

        let page = app.exportModelAsHtml().execute(
            ExportModelAsHtmlRequest(
                threatPictures: [key: "payments-threat-1.svg"],
                pictureSources: ["payments-threat-1.svg": "<svg id=\"one\"></svg>"],
                wholePicture: "<svg id=\"whole\"></svg>"
            )
        )

        #expect(page.html.contains("<svg id=\"one\"></svg>"))
        #expect(page.html.contains("<svg id=\"whole\"></svg>"))
        #expect(page.html.contains("<img") == false)
        #expect(page.html.contains("src=") == false)
    }

    /// `ExportModelAsHtml` reads the history, the banner and a control the
    /// way `ExportModelAsMarkdown` reads them: the Risk over time section
    /// holds the sampled history, the banner prints once, and a control
    /// draws as a checkbox rather than the literal "[x]" the Markdown writes.
    @Test func writesTheHistoryOneBannerAndARenderedCheckbox() {
        aModelWorthReporting()
        let rows = [
            RiskHistoryRow(
                commit: SourceCommit(
                    hash: "bbbbbbbbbbbb", shortHash: "bbbbbbb", author: "Ada",
                    date: Date(timeIntervalSince1970: 1_700_000_000), subject: "now"
                ),
                numbers: RiskHistoryNumbers(
                    totalScore: 20, worstScore: 9, threatCount: 4,
                    acceptedRisks: 0, openAttackTrees: 0, catalogueTag: nil
                )
            ),
            RiskHistoryRow(
                commit: SourceCommit(
                    hash: "aaaaaaaaaaaa", shortHash: "aaaaaaa", author: "Ada",
                    date: Date(timeIntervalSince1970: 1_600_000_000), subject: "then"
                ),
                numbers: RiskHistoryNumbers(
                    totalScore: 30, worstScore: 9, threatCount: 6,
                    acceptedRisks: 0, openAttackTrees: 0, catalogueTag: nil
                )
            )
        ]
        let template = ReportTemplate(
            frontMatter: ReportTemplate.FrontMatter(banner: "OFFICIAL"),
            pieces: ExportModelAsMarkdown.defaultTemplate.pieces
        )

        let page = app.exportModelAsHtml().execute(
            ExportModelAsHtmlRequest(template: template, history: rows)
        )

        #expect(page.html.contains("<h2>Risk over time</h2>"))
        // The banner text appears once: the fixed div, and nowhere else.
        #expect(page.html.components(separatedBy: "OFFICIAL").count == 2)
        #expect(page.html.contains("<input type=\"checkbox\""))
        #expect(page.html.contains("[ ]") == false)
        #expect(page.html.contains("[x]") == false)
    }

    @Test func linksAPictureItWasNotGiven() {
        aModelWorthReporting()
        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
        guard let first = report.rollups.topResidual.first else {
            Issue.record("the model raised no threat to picture")
            return
        }
        let key = MarkdownThreatPictures.key(threatId: first.threatId, sourceId: first.sourceId)

        let page = app.exportModelAsHtml().execute(
            ExportModelAsHtmlRequest(threatPictures: [key: "payments-threat-1.svg"])
        )

        #expect(page.html.contains("src=\"payments-threat-1.svg\""))
    }
}
