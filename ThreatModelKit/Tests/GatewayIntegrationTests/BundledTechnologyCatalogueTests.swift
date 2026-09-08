import Testing
import ThreatModelKit
@testable import CatalogueGateways

struct BundledTechnologyCatalogueTests {
    private let catalogue: BundledTechnologyCatalogue

    init() throws {
        catalogue = try BundledTechnologyCatalogue()
    }

    @Test func loadsEveryVendoredTechnology() {
        #expect(catalogue.all().count == 277)
    }

    @Test func listsProvidersByIdAscending() {
        #expect(catalogue.providers().map(\.id.value) == ["aws", "azure", "gcp", "saas", "self-hosted"])
        #expect(catalogue.providers().first?.displayName == "Amazon Web Services")
    }

    @Test func ranksSeveritiesInTaxonomyOrder() {
        let severities = catalogue.taxonomy().severities
        #expect(severities.map(\.id) == ["low", "medium", "high", "critical"])
        #expect(severities.map(\.rank) == [1, 2, 3, 4])
    }

    @Test func loadsTheRestOfTheTaxonomy() {
        #expect(catalogue.taxonomy().stride.count == 6)
        #expect(catalogue.taxonomy().categories.count == 14)
        #expect(catalogue.taxonomy().category(id: CategoryId("compute"))?.label == "Compute")
    }

    @Test func findsATechnologyById() throws {
        let ec2 = try #require(catalogue.findById(TechnologyId("aws-ec2")))
        #expect(ec2.name == "EC2")
        #expect(ec2.provider == ProviderId("aws"))
        #expect(ec2.category == CategoryId("compute"))
        #expect(ec2.description == "Virtual servers in the cloud")
        #expect(ec2.enforcesEncryption == false)
        #expect(ec2.threatIds.count == 10)
    }

    @Test func carriesTechnologySpecificContextAndMitigations() throws {
        let ec2 = try #require(catalogue.findById(TechnologyId("aws-ec2")))
        #expect(ec2.threatContext[ThreatId("credential-theft")]?.contains("169.254.169.254") == true)
        #expect(ec2.threatMitigations[ThreatId("credential-theft")]?.count == 3)
        #expect(ec2.threatMitigations[ThreatId("misconfiguration")]?.count == 4)
    }

    @Test func returnsNilForAnUnknownTechnology() {
        #expect(catalogue.findById(TechnologyId("aws-nope")) == nil)
    }

    @Test func resolvesThreatsInTheOrderTheTechnologyDeclaresThem() {
        let threats = catalogue.threatsFor(technologyId: TechnologyId("aws-ec2"))
        #expect(threats.map(\.id.value) == [
            "unauthorized-access",
            "misconfiguration",
            "malware-infection",
            "data-exfiltration",
            "privilege-escalation",
            "dos-attack",
            "credential-theft",
            "lateral-movement",
            "unpatched-vulnerabilities",
            "ssrf-attack"
        ])
    }

    @Test func resolvesSeverityFromTheTaxonomy() throws {
        let threats = catalogue.threatsFor(technologyId: TechnologyId("aws-ec2"))
        let credentialTheft = try #require(threats.first { $0.id == ThreatId("credential-theft") })
        #expect(credentialTheft.severity.id == "critical")
        #expect(credentialTheft.severity.rank == 4)
        #expect(credentialTheft.isPathwayThreat)
        #expect(credentialTheft.controls.count == 5)
        #expect(credentialTheft.mitreTechniques.isEmpty == false)
    }

    @Test func flagsConnectionAndZoneThreats() throws {
        let threats = catalogue.threatsFor(technologyId: TechnologyId("aws-ec2"))
        let unauthorised = try #require(threats.first { $0.id == ThreatId("unauthorized-access") })
        #expect(unauthorised.isZoneThreat)
        #expect(unauthorised.isConnectionThreat == false)
    }

    @Test func returnsNoThreatsForAnUnknownTechnology() {
        #expect(catalogue.threatsFor(technologyId: TechnologyId("aws-nope")).isEmpty)
    }

    @Test func listsTheConnectionThreatsTheVendoredDataFlags() throws {
        let catalogue = try BundledTechnologyCatalogue()

        #expect(catalogue.connectionThreats().map(\.id.value) == [
            "connection-mitm",
            "connection-data-exposure",
            "connection-replay",
            "connection-injection",
            "connection-dos"
        ])
    }
}
