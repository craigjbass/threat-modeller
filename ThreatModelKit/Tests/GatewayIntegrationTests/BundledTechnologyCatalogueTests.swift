import Testing
import ThreatModelKit
@testable import CatalogueGateways

struct BundledTechnologyCatalogueTests {
    private let catalogue: BundledTechnologyCatalogue

    init() throws {
        catalogue = try BundledTechnologyCatalogue()
    }

    @Test func loadsEveryVendoredTechnologyAndEveryActor() {
        let vendored = catalogue.all().filter { $0.provider != ProviderId("actor") }
        let actors = catalogue.all().filter { $0.provider == ProviderId("actor") }

        #expect(vendored.count == 277)
        #expect(actors.count == 9)
        #expect(catalogue.all().count == 286)
    }

    @Test func listsTheVendoredProvidersFirstAndTheActorsLast() {
        // The actors are ours, not a cloud, so they sit at the end of the
        // palette rather than in the middle of the vendored providers.
        #expect(catalogue.providers().map(\.id.value)
                == ["aws", "azure", "gcp", "saas", "self-hosted", "actor"])
        #expect(catalogue.providers().first?.displayName == "Amazon Web Services")
        #expect(catalogue.providers().last?.displayName == "External Actors")
    }

    @Test func ranksSeveritiesInTaxonomyOrder() {
        let severities = catalogue.taxonomy().severities
        #expect(severities.map(\.id) == ["low", "medium", "high", "critical"])
        #expect(severities.map(\.rank) == [1, 2, 3, 4])
    }

    @Test func loadsTheRestOfTheTaxonomy() {
        #expect(catalogue.taxonomy().stride.count == 6)
        // Fourteen vendored categories, plus the four the actors bring.
        #expect(catalogue.taxonomy().categories.count == 18)
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

    @Test func listsTheZoneThreatsTheVendoredDataFlags() throws {
        let catalogue = try BundledTechnologyCatalogue()

        #expect(catalogue.zoneThreats().map(\.id.value) == [
            "unauthorized-access",
            "misconfiguration",
            "data-exfiltration",
            "audit-logging-bypass",
            "network-misconfiguration",
            "lateral-movement"
        ])
    }

    @Test func listsThePathwayMitigationsTheVendoredDataHolds() throws {
        let catalogue = try BundledTechnologyCatalogue()

        #expect(catalogue.pathwayMitigations().map(\.id.value) == [
            "ddos-protection",
            "waf-protection",
            "rate-limiting",
            "network-firewall"
        ])

        let waf = try #require(catalogue.pathwayMitigations().first { $0.id.value == "waf-protection" })
        #expect(waf.label == "WAF Protection")
        #expect(waf.mitigatesThreatIds.map(\.value).contains("connection-injection"))
        #expect(waf.technologyIds.map(\.value).contains("aws-waf"))
    }

    @Test func reportsTheVersionItWasVendoredAt() throws {
        let version = try BundledTechnologyCatalogue().version()

        #expect(version.repository == "jib1337/threat-model-library")
        #expect(version.tag == "v1.0.1")
    }

    @Test func offersThePeopleAndSystemsOutsideTheBoundary() throws {
        let catalogue = try BundledTechnologyCatalogue()

        let actors = catalogue.all().filter { $0.provider == ProviderId("actor") }
        #expect(actors.map(\.id.value).sorted() == [
            "actor-admin",
            "actor-api-client",
            "actor-attacker",
            "actor-browser",
            "actor-desktop",
            "actor-iot",
            "actor-mobile",
            "actor-partner",
            "actor-user"
        ])

        // An actor raises no threats of its own. A link to one raises the
        // connection threats like any other link.
        #expect(actors.allSatisfy { $0.threatIds.isEmpty })
        #expect(actors.allSatisfy { catalogue.threatsFor(technologyId: $0.id).isEmpty })

        let user = try #require(catalogue.findById(TechnologyId("actor-user")))
        #expect(user.name.isEmpty == false)
        #expect(user.description.isEmpty == false)
    }

    @Test func widensTheProviderAndCategoryVocabularies() throws {
        let catalogue = try BundledTechnologyCatalogue()

        let actor = try #require(catalogue.providers().first { $0.id == ProviderId("actor") })
        #expect(actor.displayName == "External Actors")

        let categories = catalogue.taxonomy().categories.map(\.id.value)
        for expected in ["person", "client", "device", "system"] {
            #expect(categories.contains(expected))
        }
    }

    @Test func keepsTheActorsOutOfTheVendoredLibrary() {
        // The catalogue update script rewrites Library/. App-owned data must
        // not live where a script overwrites it.
        #expect(throws: (any Error).self) {
            try LibraryResources.data(named: "actors.json")
        }
    }
}
