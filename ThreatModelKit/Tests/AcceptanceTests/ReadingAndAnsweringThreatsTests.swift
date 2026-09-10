import Testing
import ThreatModelKit
import TestSupport

/// Given threats raised against my model
/// When I record the controls I have and correct a severity
/// Then the summary and the cards follow
struct ReadingAndAnsweringThreatsTests {
    private let app = TestDependencies()

    private func add(_ technologyId: String, sensitivity: String) -> String {
        let response = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 100, y: 100, sensitivity: sensitivity)
        )
        guard case .added(let componentId) = response else {
            Issue.record("Expected the component to be added, got \(response)")
            return ""
        }
        return componentId
    }

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    private func threat(_ threatId: String) throws -> AssessedThreat {
        try #require(threats().first { $0.threatId == threatId })
    }

    private func summary() -> SummariseRiskResponse {
        app.summariseRisk().execute(SummariseRiskRequest())
    }

    @Test func showsEveryThreatWithItsTagsTechniquesAndControls() throws {
        _ = add("aws-ec2", sensitivity: "confidential")

        let theft = try threat("credential-theft")
        #expect(theft.severityLabel == "Critical")
        #expect(theft.riskScore == 12)
        #expect(theft.stride == ["spoofing"])
        #expect(theft.mitreTechniques.map(\.id) == ["T1552"])
        #expect(theft.controls.map(\.description) == [
            "Enforce IMDSv2 to block SSRF-based credential theft",
            "Use IAM roles with minimal permissions"
        ])
        #expect(theft.controls.allSatisfy { $0.isImplemented == false })
        #expect(theft.controls.allSatisfy { $0.key.isEmpty == false })
    }

    @Test func recordsAControlTheUserTicks() throws {
        _ = add("aws-ec2", sensitivity: "confidential")
        let control = try #require(try threat("credential-theft").controls.first)

        #expect(app.recordControlImplemented().execute(
            RecordControlImplementedRequest(controlKey: control.key)
        ) == .recorded)

        let after = try threat("credential-theft")
        #expect(after.controls.first?.isImplemented == true)
        // One of the two controls now stands implemented, so the control
        // coverage stage takes the score from 12 to 8.
        #expect(after.riskScore == 8)
        #expect(summary().controlsRecorded == 1)

        #expect(app.recordControlNotImplemented().execute(
            RecordControlNotImplementedRequest(controlKey: control.key)
        ) == .recorded)
        #expect(try threat("credential-theft").controls.first?.isImplemented == false)
        #expect(summary().controlsRecorded == 0)
    }

    @Test func correctsASeverityTheCatalogueGotWrongForThisSystem() throws {
        _ = add("aws-ec2", sensitivity: "confidential")
        let key = try threat("credential-theft").overrideKey

        #expect(app.overrideThreatSeverity().execute(
            OverrideThreatSeverityRequest(overrideKey: key, severityId: "low")
        ) == .overridden)

        let lowered = try threat("credential-theft")
        #expect(lowered.severityLabel == "Low")
        #expect(lowered.riskScore == 3)
        #expect(lowered.riskLevel == "low")
        #expect(lowered.overriddenSeverityId == "low")
        #expect(summary().byLevel.first { $0.levelId == "critical" }?.count == 0)

        #expect(app.clearSeverityOverride().execute(
            ClearSeverityOverrideRequest(overrideKey: key)
        ) == .cleared)
        #expect(try threat("credential-theft").riskScore == 12)
    }

    @Test func appliesOneOverrideToEveryComponentOfThatTechnology() throws {
        _ = add("aws-ec2", sensitivity: "confidential")
        _ = add("aws-ec2", sensitivity: "confidential")
        let key = try threat("credential-theft").overrideKey

        _ = app.overrideThreatSeverity().execute(
            OverrideThreatSeverityRequest(overrideKey: key, severityId: "low")
        )

        let theft = threats().filter { $0.threatId == "credential-theft" }
        #expect(theft.count == 2)
        #expect(theft.allSatisfy { $0.severityLabel == "Low" })
    }

    @Test func summarisesTheWholeModel() throws {
        _ = add("aws-ec2", sensitivity: "confidential")

        let counted = summary()
        #expect(counted.totalThreats == threats().count)
        #expect(counted.byLevel.map(\.levelId) == ["critical", "high", "medium", "low"])
        #expect(counted.byLevel.first { $0.levelId == "critical" }?.count == 1)
        #expect(counted.byStride.first { $0.strideId == "spoofing" }?.count == 1)
        #expect(counted.controlsOffered > 0)
    }

    @Test func forgetsAComponentsTicksWhenItIsRemoved() throws {
        let web = add("aws-ec2", sensitivity: "confidential")
        let control = try #require(try threat("credential-theft").controls.first)
        _ = app.recordControlImplemented().execute(
            RecordControlImplementedRequest(controlKey: control.key)
        )
        #expect(summary().controlsRecorded == 1)

        _ = app.removeComponents().execute(RemoveComponentsRequest(componentIds: [web]))

        #expect(summary().controlsRecorded == 0)
        #expect(summary().totalThreats == 0)
    }
}
