import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// The report's Known vulnerabilities section: one row per CVE per
/// component, ordered by priority, and the sentence naming the thresholds.
@Suite("The report's Known vulnerabilities section")
struct MarkdownKnownVulnerabilitiesTests {
    private static let golden = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Goldens")
        .appendingPathComponent("known-vulnerabilities.md")

    private let rows = [
        ReportKnownVulnerability(
            cveId: "CVE-2024-7347",
            componentName: "Application Server",
            version: "1.24.0",
            cvss: 5.5,
            epss: 0.01,
            isKnownExploited: false,
            priorityLabel: "4"
        ),
        ReportKnownVulnerability(
            cveId: "CVE-2023-44487",
            componentName: "Application Server",
            version: "1.24.0",
            cvss: 7.5,
            epss: 0.94,
            isKnownExploited: true,
            priorityLabel: "1+"
        ),
        ReportKnownVulnerability(
            cveId: "CVE-2025-0001",
            componentName: "Ledger",
            version: "15.2",
            cvss: nil,
            epss: nil,
            isKnownExploited: false,
            priorityLabel: nil
        )
    ]

    @Test func writesTheGoldenSection() throws {
        let lines = MarkdownKnownVulnerabilities.lines(rows, thresholds: .default)

        let golden = try String(contentsOf: Self.golden, encoding: .utf8)
        #expect(lines.joined(separator: "\n") + "\n" == golden)
    }

    @Test func namesTheThresholdsThePolicyStates() {
        let text = MarkdownKnownVulnerabilities.lines(
            rows,
            thresholds: VulnerabilityPriority.Thresholds(cvss: 7.0, epss: 0.1)
        ).joined(separator: "\n")

        #expect(text.contains("CVSS at or above 7.0 and EPSS at or above 0.1"))
    }

    @Test func writesNoSectionForASystemStatingNoCve() {
        #expect(MarkdownKnownVulnerabilities.lines([], thresholds: .default).isEmpty)
    }

    // MARK: through the report

    private let app = TestDependencies()

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        name       = "Application Server"
        data       = "confidential"
        version    = "1.24.0"
        cves       = ["CVE-2023-44487", "CVE-2024-7347"]
      }

      component "db" {
        technology = "aws-rds"
        data       = "restricted"
      }

      flow api -> db
    }

    """

    private func aReport(policy: String? = nil) -> Report {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        _ = app.applyVulnerabilityLock().execute(
            ApplyVulnerabilityLockRequest(
                text: VulnerabilityLock(
                    cves: [
                        "CVE-2023-44487": KnownVulnerability(
                            id: "CVE-2023-44487", cvss: 7.5, epss: 0.94, isKnownExploited: true
                        )
                    ],
                    epssDate: "2026-09-15",
                    kevCatalogueVersion: "2026.09.15"
                ).text
            )
        )
        if let policy {
            _ = app.applyPolicy().execute(ApplyPolicyRequest(text: policy))
        }
        return app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
    }

    @Test func theReportHoldsOneRowPerCveOrderedByPriority() {
        let report = aReport()

        #expect(report.knownVulnerabilities.map(\.cveId) == ["CVE-2023-44487", "CVE-2024-7347"])
        #expect(report.knownVulnerabilities[0].priorityLabel == "1+")
        #expect(report.knownVulnerabilities[0].componentName == "Application Server")
        #expect(report.knownVulnerabilities[0].version == "1.24.0")
        #expect(report.knownVulnerabilities[1].priorityLabel == nil)
    }

    @Test func theReportReadsTheThresholdsFromThePolicy() {
        let report = aReport(policy: "policy {\n  cve_cvss_threshold = 8.0\n}\n")

        #expect(report.vulnerabilityThresholds == VulnerabilityPriority.Thresholds(cvss: 8.0, epss: 0.2))
    }

    @Test func theMarkdownReportWritesTheSectionAfterThirdParties() {
        _ = aReport()

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("## Known vulnerabilities"))
        #expect(markdown.contains("| [CVE-2023-44487](https://nvd.nist.gov/vuln/detail/CVE-2023-44487) | Application Server | 1.24.0 | 7.5 | 0.94 | Yes | 1+ |"))
        #expect(markdown.contains("- Likelihood: Commodity, set by CVE-2023-44487, known exploited"))
    }

    @Test func theJsonExportStatesEachRow() {
        _ = aReport()

        let json = app.exportModelAsJson().execute(ExportModelAsJsonRequest()).json

        #expect(json.contains("\"knownVulnerabilities\""))
        #expect(json.contains("\"priority\" : \"1+\""))
        #expect(json.contains("\"cveId\" : \"CVE-2024-7347\""))
    }

    @Test func theSectionNamesTheThreatsAKnownExploitedCveMoved() {
        let report = aReport()
        let moved = report.threats.filter {
            LikelihoodSource.knownExploitedCve(in: $0.likelihoodReason) == "CVE-2023-44487"
                && $0.sourceName == "Application Server"
        }

        let text = MarkdownKnownVulnerabilities.lines(
            report.knownVulnerabilities,
            thresholds: report.vulnerabilityThresholds,
            threats: report.threats
        ).joined(separator: "\n")

        #expect(moved.isEmpty == false)
        #expect(
            text.contains(
                "CVE-2023-44487 raises \(moved.map(\.name).joined(separator: ", "))"
                    + " on Application Server to Commodity."
            )
        )
    }

    @Test func theSectionNamesNoThreatWhenTheCallerStatesNone() {
        let text = MarkdownKnownVulnerabilities.lines(rows, thresholds: .default)
            .joined(separator: "\n")

        #expect(text.contains("CVE-2023-44487 raises ") == false)
    }

    @Test func theMarkdownReportNamesTheThreatsAKnownExploitedCveMoved() {
        _ = aReport()

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("CVE-2023-44487 raises "))
        #expect(markdown.contains(" on Application Server to Commodity."))
    }

    @Test func theSummaryStatesHowManyKnownExploitedCvesTheModelHolds() {
        _ = aReport()

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(
            markdown.contains(
                "This model holds 1 known exploited CVE, listed under Known vulnerabilities."
            )
        )
    }

    @Test func aTemplateNamesTheSlot() {
        #expect(ReportTemplate.Slot(rawValue: "known_vulnerabilities") == .knownVulnerabilities)
    }
}
