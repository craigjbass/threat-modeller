import Testing
import ThreatModelKit
import TestSupport

/// Given an in-house service no library holds
/// When I define it on my model and place it
/// Then it draws, it scores, and it travels in the file
struct ModellingWhatIsNotInTheCatalogueTests {
    private let app = TestDependencies()

    private func defineOurLedger(threatIds: [String] = []) -> String {
        let response = app.createCustomTechnology().execute(
            CreateCustomTechnologyRequest(
                name: "Our Ledger",
                categoryId: "database",
                description: "Keeps the balances",
                threatIds: threatIds,
                enforcesEncryption: false
            )
        )
        guard case .created(let technologyId) = response else {
            Issue.record("Expected the technology to be created, got \(response)")
            return ""
        }
        return technologyId
    }

    private func place(_ technologyId: String) -> String {
        let response = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 200, y: 200, sensitivity: "confidential")
        )
        guard case .added(let componentId) = response else {
            Issue.record("Expected the component to be added, got \(response)")
            return ""
        }
        return componentId
    }

    @Test func placesATechnologyThatIsOnlyOnThisModel() throws {
        let technologyId = defineOurLedger()
        let componentId = place(technologyId)

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())

        let component = try #require(view.components.first { $0.id == componentId })
        #expect(component.name == "Our Ledger")
        #expect(component.categoryId == "database")
        // The node draws like any other. Nothing tells the canvas this one is
        // the user's own.
        #expect(component.isUnknownTechnology == false)
    }

    @Test func showsItInThePaletteUnderTheModelsOwnGroup() throws {
        _ = defineOurLedger()

        let listed = app.listTechnologies().execute(ListTechnologiesRequest())

        let ours = try #require(listed.providers.first)
        #expect(ours.displayName == "This Model")
        #expect(ours.categories.flatMap(\.technologies).map(\.name) == ["Our Ledger"])
    }

    @Test func scoresTheThreatsISaidItCarries() throws {
        let choice = try #require(
            app.listThreatChoices().execute(ListThreatChoicesRequest()).threats.first
        )
        _ = place(defineOurLedger(threatIds: [choice.id]))

        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())

        let raised = try #require(assessment.threats.first { $0.threatId == choice.id })
        #expect(raised.source.displayName == "Our Ledger")
    }

    @Test func countsItInTheRiskSummary() throws {
        let choice = try #require(
            app.listThreatChoices().execute(ListThreatChoicesRequest()).threats.first
        )
        _ = place(defineOurLedger(threatIds: [choice.id]))

        let summary = app.summariseRisk().execute(SummariseRiskRequest())

        #expect(summary.totalThreats > 0)
    }

    @Test func keepsItWhenTheFileIsSavedAndOpenedAgain() throws {
        let choice = try #require(
            app.listThreatChoices().execute(ListThreatChoicesRequest()).threats.first
        )
        _ = place(defineOurLedger(threatIds: [choice.id]))
        let saved = app.saveThreatModel().execute(SaveThreatModelRequest())
        guard case .saved(let data) = saved else {
            Issue.record("Expected the model to be saved, got \(saved)")
            return
        }

        let reopened = TestDependencies()
        let opened = reopened.openThreatModel().execute(OpenThreatModelRequest(data: data))

        guard case .opened(_, let drift) = opened else {
            Issue.record("Expected the model to be opened, got \(opened)")
            return
        }
        // A technology the model defines travels in the file, so it is never
        // reported as missing from the catalogue.
        #expect(drift.unknownTechnologyIds.isEmpty)
        let view = reopened.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.map(\.name) == ["Our Ledger"])
        #expect(
            reopened.assessThreatModel().execute(AssessThreatModelRequest())
                .threats.contains { $0.threatId == choice.id }
        )
    }

    @Test func takesTheComponentsWithItWhenIDeleteTheTechnology() throws {
        let technologyId = defineOurLedger()
        _ = place(technologyId)

        _ = app.deleteCustomTechnology().execute(
            DeleteCustomTechnologyRequest(technologyId: technologyId)
        )

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.isEmpty)
        let listed = app.listTechnologies().execute(ListTechnologiesRequest())
        #expect(listed.providers.contains { $0.displayName == "This Model" } == false)
    }
}
