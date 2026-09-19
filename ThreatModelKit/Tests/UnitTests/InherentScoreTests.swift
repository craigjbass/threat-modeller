import Foundation
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

    /// `docs/threatmodel-export.schema.json` states that `inherentScore` is
    /// the score after the zone reduction and before the controls. This
    /// drives the same catalogue two ways, with and without a private zone,
    /// to prove the zone reduction sits inside `inherentScore` already, then
    /// reads the schema's own words for the same claim.
    @Test func theSchemaDescribesTheScoreAfterTheZoneAndBeforeTheControls() throws {
        let zoneId = ZoneId("z1")
        let zoned = ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential,
                    zoneId: zoneId
                )
            ],
            zones: [Zone(id: zoneId, rect: Rect(x: -50, y: -50, width: 300, height: 300))]
        )
        let unzoned = ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential
                )
            ]
        )

        let zonedThreat = try #require(
            AssessThreatModel(models: InMemoryThreatModelGateway(zoned), catalogue: catalogue)
                .execute(AssessThreatModelRequest()).threats.first { $0.threatId == "credential-theft" }
        )
        let unzonedThreat = try #require(
            AssessThreatModel(models: InMemoryThreatModelGateway(unzoned), catalogue: catalogue)
                .execute(AssessThreatModelRequest()).threats.first { $0.threatId == "credential-theft" }
        )

        // Nothing has answered the threat, so the zone reduction is the only
        // thing that can tell the two scores apart, and inherentScore
        // already carries it.
        #expect(zonedThreat.inherentScore < unzonedThreat.inherentScore)
        #expect(zonedThreat.riskScore == zonedThreat.inherentScore)

        let description = try Self.inherentScoreDescription()
        #expect(description.contains("after the zone reduction"))
        #expect(description.contains("before"))
        #expect(description.contains("controls"))
    }

    private static func inherentScoreDescription() throws -> String {
        let path = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("docs/threatmodel-export.schema.json")
        let text = try String(contentsOf: path, encoding: .utf8)
        let schema = try #require(
            try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any]
        )
        let properties = try #require(schema["properties"] as? [String: Any])
        let threats = try #require(properties["threats"] as? [String: Any])
        let items = try #require(threats["items"] as? [String: Any])
        let threatProperties = try #require(items["properties"] as? [String: Any])
        let inherentScore = try #require(threatProperties["inherentScore"] as? [String: Any])
        return try #require(inherentScore["description"] as? String)
    }
}
