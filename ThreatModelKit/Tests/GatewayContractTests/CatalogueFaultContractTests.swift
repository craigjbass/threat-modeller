import Foundation
import Testing
import ThreatModelKit
import TestSupport
import CatalogueGateways

/// A reader that answers with the vendored files, with one file replaced.
private struct EditedCatalogueResources: CatalogueResourceReader {
    let fileName: String
    let edit: @Sendable (Data) throws -> Data

    func data(named name: String) throws -> Data {
        let read = try LibraryResources.data(named: name)
        return name == fileName ? try edit(read) : read
    }

    func appOwnedData(named name: String) throws -> Data {
        try LibraryResources.appOwnedData(named: name)
    }
}

/// Copies the first service in a provider file and gives the copy a new name,
/// so the file declares one id twice.
private func withTheFirstServiceCopied(_ data: Data) throws -> Data {
    var file = try #require(
        try JSONSerialization.jsonObject(with: data) as? [String: Any]
    )
    var services = try #require(file["services"] as? [[String: Any]])
    var copy = try #require(services.first)
    copy["name"] = "The second entry for the same id"
    services.append(copy)
    file["services"] = services
    return try JSONSerialization.data(withJSONObject: file)
}

/// Points the first service at a threat id no threat file declares.
private func withTheFirstServicesThreatIdBroken(_ data: Data) throws -> Data {
    var file = try #require(
        try JSONSerialization.jsonObject(with: data) as? [String: Any]
    )
    var services = try #require(file["services"] as? [[String: Any]])
    services[0]["threatIds"] = ["no-such-threat"]
    file["services"] = services
    return try JSONSerialization.data(withJSONObject: file)
}

private func theFirstAwsServiceId() throws -> (id: TechnologyId, name: String) {
    let file = try #require(
        try JSONSerialization.jsonObject(
            with: try LibraryResources.data(named: "technologies/aws.json")
        ) as? [String: Any]
    )
    let services = try #require(file["services"] as? [[String: Any]])
    let first = try #require(services.first)
    return (TechnologyId(try #require(first["id"] as? String)), try #require(first["name"] as? String))
}

@Suite("A catalogue that holds a fault")
struct CatalogueFaultContractTests {
    @Test func theBundledGatewayAnswersTheDuplicateContract() throws {
        let first = try theFirstAwsServiceId()

        let subject = try BundledTechnologyCatalogue(
            resources: EditedCatalogueResources(
                fileName: "technologies/aws.json",
                edit: withTheFirstServiceCopied
            )
        )

        try verifyDuplicateTechnologyIdContract(
            subject,
            duplicatedId: first.id,
            keptName: first.name
        )
    }

    @Test func theFakeAnswersTheDuplicateContract() throws {
        let kept = CatalogueFixture.ec2()
        let second = Technology(
            id: kept.id,
            name: "The second entry for the same id",
            provider: kept.provider,
            category: kept.category,
            description: "",
            threatIds: []
        )

        let subject = InMemoryTechnologyCatalogue(
            technologies: [kept, CatalogueFixture.rds(), second],
            threats: CatalogueFixture.ec2Threats() + CatalogueFixture.connectionThreats()
                + CatalogueFixture.zoneThreats(),
            taxonomy: CatalogueFixture.taxonomy(),
            providers: CatalogueFixture.providers()
        )

        try verifyDuplicateTechnologyIdContract(
            subject,
            duplicatedId: kept.id,
            keptName: kept.name
        )
    }

    @Test func theBundledGatewayAnswersTheDanglingThreatContract() throws {
        let first = try theFirstAwsServiceId()

        let subject = try BundledTechnologyCatalogue(
            resources: EditedCatalogueResources(
                fileName: "technologies/aws.json",
                edit: withTheFirstServicesThreatIdBroken
            )
        )

        try verifyDanglingThreatIdContract(
            subject,
            technologyId: first.id,
            danglingThreatId: ThreatId("no-such-threat")
        )
    }

    @Test func theFakeAnswersTheDanglingThreatContract() throws {
        let broken = Technology(
            id: TechnologyId("aws-broken"),
            name: "Broken",
            provider: ProviderId("aws"),
            category: CategoryId("compute"),
            description: "",
            threatIds: [ThreatId("no-such-threat")]
        )

        let subject = InMemoryTechnologyCatalogue(
            technologies: [CatalogueFixture.ec2(), broken],
            threats: CatalogueFixture.ec2Threats() + CatalogueFixture.connectionThreats()
                + CatalogueFixture.zoneThreats(),
            taxonomy: CatalogueFixture.taxonomy(),
            providers: CatalogueFixture.providers()
        )

        try verifyDanglingThreatIdContract(
            subject,
            technologyId: broken.id,
            danglingThreatId: ThreatId("no-such-threat")
        )
    }

    /// The check the next catalogue tag bump must pass. A dangling threat id,
    /// a duplicate technology id, or both, fails this test rather than the
    /// application.
    @Test func theVendoredCatalogueHoldsNoFault() throws {
        let faults = try BundledTechnologyCatalogue().faults()

        #expect(faults.map(\.message) == [])
    }
}
