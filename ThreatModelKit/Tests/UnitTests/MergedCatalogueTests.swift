import Testing
import TestSupport
@testable import ThreatModelKit

@Suite("The merged catalogue")
struct MergedCatalogueTests {
    private func aLibrary() -> Library {
        Library(
            label: "acme",
            provider: Provider(id: ProviderId("acme"), displayName: "Acme Platform"),
            technologies: [
                Technology(
                    id: TechnologyId("acme-cribl-stream"),
                    name: "Cribl Stream",
                    provider: ProviderId("acme"),
                    category: CategoryId("compute"),
                    description: "",
                    threatIds: [ThreatId("acme-pipeline-tamper"), ThreatId("misconfiguration")]
                )
            ],
            threats: [
                Threat(
                    id: ThreatId("acme-pipeline-tamper"),
                    name: "Pipeline tampering",
                    description: "An attacker rewrites a pipeline.",
                    severity: CatalogueFixture.high,
                    stride: [StrideId("tampering")],
                    controls: [Control(id: "acme-pipeline-tamper-0", description: "Sign pipelines")]
                ),
                Threat(
                    id: ThreatId("acme-in-transit"),
                    name: "In transit",
                    description: "An attacker reads what crosses the link.",
                    severity: CatalogueFixture.medium,
                    controls: [Control(id: "acme-in-transit-0", description: "Use TLS")],
                    isConnectionThreat: true
                ),
                Threat(
                    id: ThreatId("acme-in-zone"),
                    name: "In zone",
                    description: "An attacker moves inside the zone.",
                    severity: CatalogueFixture.low,
                    controls: [Control(id: "acme-in-zone-0", description: "Watch the zone")],
                    isZoneThreat: true,
                    zoneContext: "A private zone holds it."
                )
            ]
        )
    }

    @Test func readsExactlyTheBaseWhenItHoldsNoLibrary() {
        let base = CatalogueFixture.catalogue()

        let merged = MergedCatalogue(base: base, store: LibraryStore())

        #expect(merged.all() == base.all())
        #expect(merged.providers() == base.providers())
        #expect(merged.version() == base.version())
        #expect(merged.taxonomy() == base.taxonomy())
        #expect(merged.connectionThreats() == base.connectionThreats())
        #expect(merged.zoneThreats() == base.zoneThreats())
        #expect(merged.pathwayMitigations() == base.pathwayMitigations())
    }

    @Test func meetsTheCatalogueContractWithNoLibrary() throws {
        try verifyTechnologyCatalogueContract(
            MergedCatalogue(base: CatalogueFixture.catalogue(), store: LibraryStore()),
            knownTechnologyId: TechnologyId("aws-ec2")
        )
    }

    @Test func meetsTheCatalogueContractWithALibrary() throws {
        try verifyTechnologyCatalogueContract(
            MergedCatalogue(base: CatalogueFixture.catalogue(), store: LibraryStore([aLibrary()])),
            knownTechnologyId: TechnologyId("acme-cribl-stream")
        )
    }

    @Test func findsALibraryTechnology() throws {
        let merged = MergedCatalogue(
            base: CatalogueFixture.catalogue(),
            store: LibraryStore([aLibrary()])
        )

        let found = try #require(merged.findById(TechnologyId("acme-cribl-stream")))
        #expect(found.name == "Cribl Stream")
    }

    @Test func readsALibraryTechnologysThreatsInTheOrderItDeclaresThem() {
        let merged = MergedCatalogue(
            base: CatalogueFixture.catalogue(),
            store: LibraryStore([aLibrary()])
        )

        #expect(
            merged.threatsFor(technologyId: TechnologyId("acme-cribl-stream")).map(\.id.value)
                == ["acme-pipeline-tamper", "misconfiguration"]
        )
    }

    @Test func addsOneProviderForEachLibrary() {
        let base = CatalogueFixture.catalogue()

        let merged = MergedCatalogue(base: base, store: LibraryStore([aLibrary()]))

        #expect(merged.providers().count == base.providers().count + 1)
        #expect(merged.providers().last?.id == ProviderId("acme"))
    }

    @Test func addsALibrarysConnectionAndZoneThreats() {
        let base = CatalogueFixture.catalogue()

        let merged = MergedCatalogue(base: base, store: LibraryStore([aLibrary()]))

        #expect(merged.connectionThreats().map(\.id.value).contains("acme-in-transit"))
        #expect(merged.zoneThreats().map(\.id.value).contains("acme-in-zone"))
        #expect(merged.connectionThreats().count == base.connectionThreats().count + 1)
    }

    @Test func readsTheStoreEveryTimeRatherThanOnce() {
        let store = LibraryStore()
        let merged = MergedCatalogue(base: CatalogueFixture.catalogue(), store: store)
        #expect(merged.findById(TechnologyId("acme-cribl-stream")) == nil)

        store.set([aLibrary()])

        #expect(merged.findById(TechnologyId("acme-cribl-stream")) != nil)
    }
}
