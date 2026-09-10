import Testing
import ThreatModelKit
import TestSupport

struct InherentScoreTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func model() -> ThreatModel {
        ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential
                )
            ],
            controlStatuses: [
                ControlIdentity.componentControl(
                    componentId: ComponentId("c1"),
                    threatId: ThreatId("credential-theft"),
                    description: "Enforce IMDSv2 to block SSRF-based credential theft",
                    isTechnologySpecific: true
                ): .implemented
            ]
        )
    }

    @Test func theAssessmentStatesBothScores() throws {
        let response = AssessThreatModel(
            models: InMemoryThreatModelGateway(model()),
            catalogue: catalogue
        ).execute(AssessThreatModelRequest())
        let threat = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(threat.riskScore == 8)
        #expect(threat.inherentScore == 12)
    }

    @Test func theReportStatesBothScores() throws {
        let report = BuildThreatModelReport(
            models: InMemoryThreatModelGateway(model()),
            catalogue: catalogue
        ).execute(BuildThreatModelReportRequest()).report
        let threat = try #require(report.threats.first { $0.threatId == "credential-theft" })
        #expect(threat.riskScore == 8)
        #expect(threat.inherentScore == 12)
    }

    @Test func theMarkdownStatesWhatTheControlsBought() {
        let markdown = ExportModelAsMarkdown(
            reports: BuildThreatModelReport(
                models: InMemoryThreatModelGateway(model()),
                catalogue: catalogue
            )
        ).execute(ExportModelAsMarkdownRequest()).markdown
        #expect(markdown.contains("- Risk: high (8), before controls 12"))
    }
}
