import Testing
import ThreatModelKit
import TestSupport

@Suite("Saying what a node is and what it holds")
struct SetComponentPropertiesTests {
    private let app = TestDependencies()

    private func aComponent(_ technologyId: String = "aws-ec2") -> String {
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 0, y: 0, sensitivity: "internal")
        ) else {
            Issue.record("the component was not added")
            return ""
        }
        return componentId
    }

    private func set(
        _ componentId: String,
        name: String? = nil,
        sensitivity: String = "internal",
        threatsDisabled: Bool = false
    ) -> SetComponentPropertiesResponse {
        app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: componentId,
                name: name,
                sensitivity: sensitivity,
                threatsDisabled: threatsDisabled
            )
        )
    }

    private func view() -> ViewThreatModelResponse {
        app.viewThreatModel().execute(ViewThreatModelRequest())
    }

    @Test func namesTheNodeWhatTheUserCalledIt() throws {
        let componentId = aComponent()

        #expect(set(componentId, name: "Checkout Server") == .updated)

        #expect(try #require(view().components.first).name == "Checkout Server")
    }

    @Test func goesBackToTheTechnologyNameWhenTheUserClearsIt() throws {
        let componentId = aComponent()
        _ = set(componentId, name: "Checkout Server")

        _ = set(componentId, name: "   ")

        #expect(try #require(view().components.first).name == "EC2")
    }

    @Test func raisesTheScoreWhenTheDataIsMoreSensitive() {
        let componentId = aComponent()
        let before = app.assessThreatModel().execute(AssessThreatModelRequest())

        _ = set(componentId, sensitivity: "restricted")

        let after = app.assessThreatModel().execute(AssessThreatModelRequest())
        #expect(after.threats.count == before.threats.count)
        #expect((after.threats.first?.riskScore ?? 0) > (before.threats.first?.riskScore ?? 0))
    }

    @Test func refusesASensitivityTheApplicationDoesNotHold() {
        let componentId = aComponent()

        #expect(set(componentId, sensitivity: "top-secret") == .unknownSensitivity)
    }

    @Test func refusesANodeTheModelDoesNotHold() {
        #expect(set("no-such-component") == .unknownComponent)
    }

    @Test func raisesNothingForANodeWhoseThreatsAreOff() {
        let componentId = aComponent()

        _ = set(componentId, threatsDisabled: true)

        #expect(app.assessThreatModel().execute(AssessThreatModelRequest()).threats.isEmpty)
        // The node stays on the diagram. It is silenced, not deleted.
        #expect(view().components.count == 1)
        #expect(view().components.first?.threatsDisabled == true)
    }

    @Test func costsOneUndo() throws {
        let componentId = aComponent()
        _ = set(componentId, name: "Checkout Server", sensitivity: "restricted")

        _ = app.undoLastChange().execute(UndoLastChangeRequest())

        let component = try #require(view().components.first)
        #expect(component.name == "EC2")
        #expect(component.sensitivityId == "internal")
    }
}
