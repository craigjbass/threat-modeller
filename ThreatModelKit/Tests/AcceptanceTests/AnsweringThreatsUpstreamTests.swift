import Testing
import ThreatModelKit
import TestSupport

/// Given a control sitting in front of my application
/// When I say that control is real on my system
/// Then the threats it answers fall, and a threat feeding sensitive data rises
struct AnsweringThreatsUpstreamTests {
    private let app = TestDependencies()

    private func add(_ technologyId: String, sensitivity: String) -> String {
        let response = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 0, y: 0, sensitivity: sensitivity)
        )
        guard case .added(let componentId) = response else {
            Issue.record("Expected the component to be added, got \(response)")
            return ""
        }
        return componentId
    }

    private func connect(_ source: String, _ target: String) {
        let response = app.connectComponents().execute(
            ConnectComponentsRequest(sourceComponentId: source, targetComponentId: target)
        )
        guard case .connected = response else {
            Issue.record("Expected the link to be made, got \(response)")
            return
        }
    }

    private func threat(_ threatId: String, from sourceId: String) -> AssessedThreat? {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
            .first { $0.threatId == threatId && $0.source.id == sourceId }
    }

    private func turnOn(_ mitigationId: String, mode: String, percent: Int) {
        #expect(app.configurePathwayMitigations().execute(
            ConfigurePathwayMitigationsRequest(
                isMasterEnabled: true,
                mitigationId: mitigationId,
                isEnabled: true,
                mode: mode,
                reductionPercent: percent
            )
        ) == .configured)
    }

    @Test func raisesAThreatThatFeedsMoreSensitiveData() throws {
        let web = add("aws-ec2", sensitivity: "public")
        let database = add("aws-rds", sensitivity: "restricted")

        // Alone, credential theft on public data is critical (4) x public (1).
        #expect(threat("credential-theft", from: "component:\(web)")?.riskScore == 4)

        connect(web, database)

        // Feeding restricted data, it is scored against restricted.
        let escalated = try #require(threat("credential-theft", from: "component:\(web)"))
        #expect(escalated.sensitivityId == "restricted")
        #expect(escalated.riskScore == 16)
        #expect(escalated.riskLevel == "critical")
    }

    @Test func showsWhichMitigationsThisModelCanUse() throws {
        let listed = app.listPathwayMitigations().execute(ListPathwayMitigationsRequest())

        #expect(listed.isMasterEnabled == false)
        let waf = try #require(listed.mitigations.first { $0.id == "waf-protection" })
        #expect(waf.isProvidedOnThisModel == false)
        #expect(waf.providedByTechnologyNames == ["WAF"])

        _ = add("aws-waf", sensitivity: "internal")

        let after = app.listPathwayMitigations().execute(ListPathwayMitigationsRequest())
        #expect(try #require(after.mitigations.first).isProvidedOnThisModel)
    }

    @Test func lowersTheThreatsAControlInFrontAnswers() throws {
        let firewall = add("aws-waf", sensitivity: "internal")
        let web = add("aws-ec2", sensitivity: "confidential")
        connect(firewall, web)

        #expect(threat("credential-theft", from: "component:\(web)")?.riskScore == 12)

        turnOn("waf-protection", mode: "reduce", percent: 50)

        let lowered = try #require(threat("credential-theft", from: "component:\(web)"))
        #expect(lowered.riskScore == 6)
        #expect(lowered.scoreBeforePathwayMitigation == 12)
        #expect(lowered.pathwayMitigationLabels == ["WAF Protection"])
    }

    @Test func dropsTheThreatEntirelyWhenTheUserSaysRemove() throws {
        let firewall = add("aws-waf", sensitivity: "internal")
        let web = add("aws-ec2", sensitivity: "confidential")
        connect(firewall, web)

        turnOn("waf-protection", mode: "remove", percent: 0)

        #expect(threat("credential-theft", from: "component:\(web)") == nil)
        // Everything the mitigation does not answer stays.
        #expect(threat("misconfiguration", from: "component:\(web)") != nil)
    }

    @Test func changesNothingUntilTheUserSaysTheControlIsReal() throws {
        let firewall = add("aws-waf", sensitivity: "internal")
        let web = add("aws-ec2", sensitivity: "confidential")
        connect(firewall, web)

        // The catalogue knows the WAF provides the mitigation. The score does
        // not move until the master toggle goes on.
        #expect(threat("credential-theft", from: "component:\(web)")?.riskScore == 12)

        turnOn("waf-protection", mode: "reduce", percent: 50)
        #expect(threat("credential-theft", from: "component:\(web)")?.riskScore == 6)

        #expect(app.configurePathwayMitigations().execute(
            ConfigurePathwayMitigationsRequest(
                isMasterEnabled: false,
                mitigationId: nil,
                isEnabled: true,
                mode: "reduce",
                reductionPercent: 50
            )
        ) == .configured)
        #expect(threat("credential-theft", from: "component:\(web)")?.riskScore == 12)
    }

    @Test func lowersALinksThreatsFromWhatIsInFrontOfItsSource() throws {
        let firewall = add("aws-waf", sensitivity: "internal")
        let web = add("aws-ec2", sensitivity: "internal")
        let database = add("aws-rds", sensitivity: "internal")
        connect(firewall, web)
        connect(web, database)

        let link = try #require(
            app.viewThreatModel().execute(ViewThreatModelRequest()).connections
                .first { $0.sourceComponentId == web }
        ).id

        #expect(threat("connection-dos", from: "connection:\(link)")?.riskScore == 2)

        turnOn("waf-protection", mode: "reduce", percent: 50)

        #expect(threat("connection-dos", from: "connection:\(link)")?.riskScore == 1)
    }

    @Test func summarisesWhatTheMitigationLeaves() throws {
        let firewall = add("aws-waf", sensitivity: "internal")
        let web = add("aws-ec2", sensitivity: "confidential")
        connect(firewall, web)
        let before = app.summariseRisk().execute(SummariseRiskRequest())

        turnOn("waf-protection", mode: "remove", percent: 0)

        let after = app.summariseRisk().execute(SummariseRiskRequest())
        #expect(after.totalThreats < before.totalThreats)
        #expect(after.totalThreats
                == app.assessThreatModel().execute(AssessThreatModelRequest()).threats.count)
    }
}
