import Testing
import ThreatModelKit
import TestSupport

/// Reads a built report's sections against each other, not against a
/// hand-made value: `BuildThreatModelReport` computes the Findings cut and
/// the leverage actions once, so every section a reader turns to states the
/// same numbers.
struct ReportSectionsTests {
    private func report(for model: ThreatModel) -> Report {
        BuildThreatModelReport(
            models: InMemoryThreatModelGateway(model),
            catalogue: CatalogueFixture.catalogue()
        ).execute(BuildThreatModelReportRequest()).report
    }

    private func ec2Components(_ count: Int) -> [Component] {
        (0..<count).map { index in
            Component(
                id: ComponentId("c\(index)"),
                technologyId: TechnologyId("aws-ec2"),
                position: Point(x: Double(index * 10), y: 0),
                sensitivity: .restricted
            )
        }
    }

    @Test func theVerdictSentenceAndTheFindingsSectionAgreeOnHowManyThreatsSitAboveTolerance() {
        let report = report(for: ThreatModel(components: ec2Components(3)))

        let above = report.findings.above.count + report.findings.notShown
        #expect(above >= 2)
        #expect(report.executiveSummary.verdict.contains("\(above) residual exposures"))
    }

    @Test func theVerdictAndFindingsAgreeEvenWhenQualifyingThreatsExceedTheFindingsMaximum() {
        let report = report(for: ThreatModel(components: ec2Components(30)))

        let above = report.findings.above.count + report.findings.notShown
        #expect(above > ReportFindingsCut.maximum)
        #expect(report.findings.above.count == ReportFindingsCut.maximum)
        #expect(report.findings.notShown == above - ReportFindingsCut.maximum)
        #expect(report.executiveSummary.verdict.contains("\(above) residual exposures"))
    }

    @Test func everyActionTheExecutiveSummaryNamesIsInTheActionsSectionWithTheSameTextAndLeverage() throws {
        let guardComponent = Component(
            id: ComponentId("guard"),
            technologyId: TechnologyId("aws-waf"),
            position: Point(x: 0, y: 0),
            sensitivity: .restricted
        )
        let stores = (1...4).map { index in
            Component(
                id: ComponentId("store\(index)"),
                technologyId: TechnologyId("aws-rds"),
                position: Point(x: Double(index * 100), y: 0),
                sensitivity: .restricted
            )
        }
        let reductions = [90, 70, 50, 10]
        let edges = (1...4).map { index in
            MitigatesEdge(
                source: ComponentId("guard"),
                target: ComponentId("store\(index)"),
                threatIds: [ThreatId("misconfiguration")],
                status: .proposed,
                action: EdgeAction(label: "action-\(index)", text: "Do thing \(index)")
            )
        }
        let model = ThreatModel(components: [guardComponent] + stores, mitigatesEdges: edges)

        let report = report(for: model)

        #expect(report.actions.count == 4)
        #expect(report.executiveSummary.topLeverageActions.isEmpty == false)
        #expect(report.executiveSummary.topLeverageActions.count < report.actions.count)

        for named in report.executiveSummary.topLeverageActions {
            let inActionsSection = try #require(report.actions.first { $0.label == named.label })
            #expect(inActionsSection.text == named.text)
            #expect(inActionsSection.removes == named.removes)
        }
    }

    @Test func aReportWithNoNewDataHoldsEmptySections() {
        let report = BuildThreatModelReport(
            models: InMemoryThreatModelGateway(ThreatModel()),
            catalogue: CatalogueFixture.catalogue()
        ).execute(BuildThreatModelReportRequest()).report

        #expect(report.recommendations.isEmpty)
        #expect(report.protectionDependencies.isEmpty)
        #expect(report.attackPaths.isEmpty)
        #expect(report.attackPathsNotListed.isEmpty)
        #expect(report.rollups.byZone.isEmpty)
        #expect(report.rollups.topResidual.isEmpty)
    }

    @Test func theMarkdownEndsWithTheAppendices() {
        let markdown = ExportModelAsMarkdown(
            reports: BuildThreatModelReport(
                models: InMemoryThreatModelGateway(ThreatModel()),
                catalogue: CatalogueFixture.catalogue()
            )
        ).execute(ExportModelAsMarkdownRequest()).markdown
        #expect(markdown.contains("## Appendix A \u{2014} Full threat register"))
        #expect(markdown.contains("## Appendix B \u{2014} Model inventory"))
        #expect(markdown.hasSuffix("### Zones\n\nNone.\n"))
    }
}
