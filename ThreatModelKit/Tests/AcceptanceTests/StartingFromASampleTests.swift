import Testing
import ThreatModelKit
import TestSupport

/// Given an example this application ships
/// When I open it and change what a node holds
/// Then the scores follow, and one undo takes each change back
struct StartingFromASampleTests {
    private let app = TestDependencies()

    private func openTheExample() -> String {
        let listed = app.listSampleModels().execute(ListSampleModelsRequest())
        guard let sample = listed.samples.first else {
            Issue.record("this application ships no examples")
            return ""
        }
        _ = app.loadSampleModel().execute(LoadSampleModelRequest(sampleId: sample.id))
        return sample.id
    }

    @Test func opensTheExampleWithItsThreatsAlreadyScored() throws {
        _ = openTheExample()

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())

        #expect(view.components.isEmpty == false)
        #expect(assessment.threats.isEmpty == false)
        #expect(app.summariseRisk().execute(SummariseRiskRequest()).totalThreats > 0)
    }

    @Test func raisesEveryScoreWhenTheDataIsMoreSensitive() throws {
        _ = openTheExample()
        let componentId = try #require(
            app.viewThreatModel().execute(ViewThreatModelRequest()).components.first
        ).id
        let before = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.source.id == "component:\(componentId)" }
        ).riskScore

        _ = app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: componentId,
                name: "The One That Matters",
                sensitivity: "restricted",
                threatsDisabled: false,
                runsAs: "user"
            )
        )

        let after = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.source.id == "component:\(componentId)" }
        )
        #expect(after.riskScore > before)
        #expect(after.source.displayName == "The One That Matters")
    }

    @Test func takesTheExampleBackWithOneUndo() {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 0, y: 0, sensitivity: "internal")
        )
        _ = openTheExample()

        _ = app.undoLastChange().execute(UndoLastChangeRequest())

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.map(\.technologyId) == ["aws-rds"])
    }

    @Test func reportsTheExampleLikeAnythingElse() {
        _ = openTheExample()

        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest())

        #expect(markdown.markdown.contains("## Threats"))
        #expect(markdown.markdown.contains("| Name | Technology | Sensitivity | Zone | Assets |"))
        #expect(markdown.markdown.contains("## Threats\n\nNone.") == false)
    }

    @Test func namesTheCatalogueTheExampleWasBuiltAgainst() {
        let version = app.viewCatalogueVersion().execute(ViewCatalogueVersionRequest())

        #expect(version.repository.isEmpty == false)
        #expect(version.tag.isEmpty == false)
        #expect(version.technologyCount > 0)
    }
}
