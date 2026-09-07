import Testing
import ThreatModelKit

struct TaxonomyTests {
    private let taxonomy = Taxonomy(
        stride: [
            StrideCategory(id: StrideId("spoofing"), label: "Spoofing"),
            StrideCategory(id: StrideId("tampering"), label: "Tampering")
        ],
        severities: [
            ThreatSeverity(id: "low", label: "Low", rank: 1),
            ThreatSeverity(id: "medium", label: "Medium", rank: 2),
            ThreatSeverity(id: "high", label: "High", rank: 3),
            ThreatSeverity(id: "critical", label: "Critical", rank: 4)
        ],
        categories: [
            ServiceCategory(
                id: CategoryId("compute"),
                label: "Compute",
                presetThreatIds: [ThreatId("misconfiguration")]
            )
        ]
    )

    @Test func findsASeverityByItsId() {
        #expect(taxonomy.severity(id: "critical")?.rank == 4)
        #expect(taxonomy.severity(id: "low")?.label == "Low")
    }

    @Test func returnsNilForAnUnknownSeverity() {
        #expect(taxonomy.severity(id: "catastrophic") == nil)
    }

    @Test func findsACategoryByItsId() {
        #expect(taxonomy.category(id: CategoryId("compute"))?.label == "Compute")
        #expect(taxonomy.category(id: CategoryId("nope")) == nil)
    }

    @Test func findsAStrideCategoryByItsId() {
        #expect(taxonomy.strideCategory(id: StrideId("tampering"))?.label == "Tampering")
    }
}
