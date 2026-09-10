import Testing
import ThreatModelKit
import TestSupport

struct ReportSectionsTests {
    @Test func aReportWithNoNewDataHoldsEmptySections() {
        let report = BuildThreatModelReport(
            models: InMemoryThreatModelGateway(ThreatModel()),
            catalogue: CatalogueFixture.catalogue()
        ).execute(BuildThreatModelReportRequest()).report

        #expect(report.recommendations.isEmpty)
        #expect(report.protectionDependencies.isEmpty)
        #expect(report.attackPaths.isEmpty)
        #expect(report.attackPathsNotListed == 0)
        #expect(report.rollups.byZone.isEmpty)
        #expect(report.rollups.topResidual.isEmpty)
    }

    @Test func theMarkdownStillEndsWithTheThreats() {
        let markdown = ExportModelAsMarkdown(
            reports: BuildThreatModelReport(
                models: InMemoryThreatModelGateway(ThreatModel()),
                catalogue: CatalogueFixture.catalogue()
            )
        ).execute(ExportModelAsMarkdownRequest()).markdown
        #expect(markdown.contains("## Threats"))
    }
}
