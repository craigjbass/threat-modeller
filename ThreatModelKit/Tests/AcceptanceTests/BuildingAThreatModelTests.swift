import Testing
import ThreatModelKit
import TestSupport

/// Given a catalogue of technologies
/// When I add one to my threat model
/// Then its threats are raised against it, scored for the data it handles
struct BuildingAThreatModelTests {
    private let app = TestDependencies()

    @Test func offersTheCatalogueGroupedForBrowsing() throws {
        let palette = app.listTechnologies().execute(ListTechnologiesRequest())

        #expect(palette.providers.map(\.displayName) == [
            "Amazon Web Services",
            "Google Cloud Platform"
        ])

        let aws = try #require(palette.providers.first { $0.id == "aws" })
        #expect(aws.categories.map(\.label) == ["Compute", "Database"])
        #expect(aws.categories.first?.technologies.map(\.name) == ["EC2"])
    }

    @Test func raisesNoThreatsBeforeAnythingIsAdded() {
        #expect(app.assessThreatModel().execute(AssessThreatModelRequest()).threats.isEmpty)
    }

    @Test func raisesTheTechnologysThreatsOnceItIsOnTheModel() throws {
        let added = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 100, y: 200, sensitivity: "confidential")
        )
        #expect(added == .added(componentId: "id-1"))

        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())

        #expect(assessment.threats.map(\.threatId) == [
            "credential-theft",
            "misconfiguration",
            "dos-attack"
        ])
        #expect(assessment.threats.map(\.riskScore) == [12, 6, 3])
        #expect(assessment.threats.map(\.riskLevel) == ["critical", "medium", "low"])
        #expect(assessment.threats.allSatisfy { $0.source.displayName == "EC2" })

        let worst = try #require(assessment.threats.first)
        #expect(worst.name == "Credential Theft")
        #expect(worst.severityLabel == "Critical")
        #expect(worst.stride == ["spoofing"])
        #expect(worst.mitreTechniques.map(\.id) == ["T1552"])
        #expect(worst.context == "Instance Metadata Service credential theft")
        #expect(worst.controls.map(\.description) == [
            "Enforce IMDSv2 to block SSRF-based credential theft",
            "Use IAM roles with minimal permissions"
        ])
    }

    @Test func scoresTheSameTechnologyLowerForLessSensitiveData() throws {
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "public")
        )

        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())
        let credentialTheft = try #require(assessment.threats.first { $0.threatId == "credential-theft" })

        #expect(credentialTheft.riskScore == 4)
        #expect(credentialTheft.riskLevel == "medium")
    }

    @Test func addsATechnologyTakenFromThePalette() throws {
        let palette = app.listTechnologies().execute(ListTechnologiesRequest())
        let technology = try #require(palette.providers.first?.categories.first?.technologies.first)

        let added = app.addComponent().execute(
            AddComponentRequest(technologyId: technology.id, x: 0, y: 0, sensitivity: "confidential")
        )

        guard case .added(let componentId) = added else {
            Issue.record("Expected the component to be added, got \(added)")
            return
        }

        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())
        #expect(assessment.threats.contains { $0.source.id == "component:\(componentId)" })
    }

    @Test func refusesATechnologyTheCatalogueDoesNotHave() {
        let response = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-imaginary", x: 0, y: 0, sensitivity: "internal")
        )

        #expect(response == .unknownTechnology)
        #expect(app.assessThreatModel().execute(AssessThreatModelRequest()).threats.isEmpty)
    }
}
