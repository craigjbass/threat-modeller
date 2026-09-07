import Testing
import ThreatModelKit
import TestSupport
import CatalogueGateways

struct TechnologyCatalogueContractTests {
    @Test func theFakeHonoursTheContract() throws {
        try verifyTechnologyCatalogueContract(
            CatalogueFixture.catalogue(),
            knownTechnologyId: TechnologyId("aws-ec2")
        )
    }

    @Test func theBundledCatalogueHonoursTheContract() throws {
        try verifyTechnologyCatalogueContract(
            try BundledTechnologyCatalogue(),
            knownTechnologyId: TechnologyId("aws-ec2")
        )
    }
}
