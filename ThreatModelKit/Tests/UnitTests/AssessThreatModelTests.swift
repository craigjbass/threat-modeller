import Testing
import ThreatModelKit
import TestSupport

struct AssessThreatModelTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func assess(_ model: ThreatModel) -> AssessThreatModelResponse {
        AssessThreatModel(models: InMemoryThreatModelGateway(model), catalogue: catalogue)
            .execute(AssessThreatModelRequest())
    }

    private func ec2(
        id: String = "c1",
        sensitivity: DataSensitivity = .confidential,
        customName: String? = nil,
        threatsDisabled: Bool = false
    ) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: sensitivity,
            customName: customName,
            threatsDisabled: threatsDisabled
        )
    }

    @Test func raisesNothingForAnEmptyModel() {
        #expect(assess(ThreatModel()).threats.isEmpty)
    }

    @Test func raisesEveryThreatTheTechnologyDeclares() {
        let response = assess(ThreatModel(components: [ec2()]))
        #expect(response.threats.map(\.threatId) == ["credential-theft", "misconfiguration", "dos-attack"])
    }

    @Test func scoresSeverityAgainstTheComponentsSensitivity() throws {
        let response = assess(ThreatModel(components: [ec2(sensitivity: .confidential)]))

        let credentialTheft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(credentialTheft.riskScore == 12)
        #expect(credentialTheft.riskLevel == "critical")
        #expect(credentialTheft.severityId == "critical")
        #expect(credentialTheft.severityLabel == "Critical")
        #expect(credentialTheft.sensitivityId == "confidential")

        let misconfiguration = try #require(response.threats.first { $0.threatId == "misconfiguration" })
        #expect(misconfiguration.riskScore == 6)
        #expect(misconfiguration.riskLevel == "medium")

        let dos = try #require(response.threats.first { $0.threatId == "dos-attack" })
        #expect(dos.riskScore == 3)
        #expect(dos.riskLevel == "low")
    }

    @Test func ordersByScoreThenThreatIdThenComponentId() {
        let response = assess(
            ThreatModel(components: [ec2(id: "c2"), ec2(id: "c1", sensitivity: .publicData)])
        )
        let ordering = response.threats.map { "\($0.riskScore):\($0.threatId):\($0.sourceComponentId)" }
        #expect(ordering == [
            "12:credential-theft:c2",
            "6:misconfiguration:c2",
            "4:credential-theft:c1",
            "3:dos-attack:c2",
            "2:misconfiguration:c1",
            "1:dos-attack:c1"
        ])
    }

    @Test func namesTheSourceAfterTheTechnologyUnlessRenamed() throws {
        let plain = assess(ThreatModel(components: [ec2()]))
        #expect(plain.threats.first?.sourceName == "EC2")
        #expect(plain.threats.first?.sourceProviderId == "aws")
        #expect(plain.threats.first?.sourceComponentId == "c1")

        let renamed = assess(ThreatModel(components: [ec2(customName: "Bastion host")]))
        #expect(renamed.threats.first?.sourceName == "Bastion host")
    }

    @Test func prefersTechnologySpecificMitigationsOverGenericControls() throws {
        let response = assess(ThreatModel(components: [ec2()]))

        let credentialTheft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        #expect(credentialTheft.controls.allSatisfy { $0.isTechnologySpecific })
        #expect(credentialTheft.controls.map(\.description) == [
            "Enforce IMDSv2 to block SSRF-based credential theft",
            "Use IAM roles with minimal permissions"
        ])

        let misconfiguration = try #require(response.threats.first { $0.threatId == "misconfiguration" })
        #expect(misconfiguration.controls.contains(where: \.isTechnologySpecific) == false)
        #expect(misconfiguration.controls.map(\.description) == ["Scan configuration continuously"])
    }

    @Test func carriesTechnologySpecificContextWhenThereIsSome() throws {
        let response = assess(ThreatModel(components: [ec2()]))
        let credentialTheft = try #require(response.threats.first { $0.threatId == "credential-theft" })
        let dos = try #require(response.threats.first { $0.threatId == "dos-attack" })

        #expect(credentialTheft.context == "Instance Metadata Service credential theft")
        #expect(dos.context == nil)
    }

    @Test func carriesStrideAndMitreThrough() throws {
        let response = assess(ThreatModel(components: [ec2()]))
        let credentialTheft = try #require(response.threats.first { $0.threatId == "credential-theft" })

        #expect(credentialTheft.stride == ["spoofing"])
        #expect(credentialTheft.mitreTechniques == [
            AssessedMitreTechnique(id: "T1552", name: "Unsecured Credentials", tactic: "Credential Access")
        ])
    }

    @Test func raisesNothingForAComponentWithThreatsDisabled() {
        let response = assess(ThreatModel(components: [ec2(threatsDisabled: true)]))
        #expect(response.threats.isEmpty)
    }

    @Test func ignoresAComponentWhoseTechnologyIsNotInTheCatalogue() {
        let orphan = Component(
            id: ComponentId("c9"),
            technologyId: TechnologyId("aws-nope"),
            position: Point(x: 0, y: 0),
            sensitivity: .restricted
        )
        #expect(assess(ThreatModel(components: [orphan])).threats.isEmpty)
    }
}
