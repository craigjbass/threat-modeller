import Testing
@testable import ThreatModelKit

@Suite("Building a library")
struct LibraryTests {
    private let taxonomy = Taxonomy(
        stride: [StrideCategory(id: StrideId("tampering"), label: "Tampering")],
        severities: [
            ThreatSeverity(id: "low", label: "Low", rank: 1),
            ThreatSeverity(id: "high", label: "High", rank: 3)
        ],
        categories: [
            ServiceCategory(id: CategoryId("monitoring"), label: "Monitoring", presetThreatIds: [])
        ]
    )

    private let source = LibrarySource(
        label: "acme",
        displayName: "Acme Platform",
        technologies: [
            SourceTechnology(
                id: "cribl-stream",
                name: "Cribl Stream",
                category: "monitoring",
                description: "Observability pipeline",
                threatIds: ["pipeline-tamper", "credential-theft"],
                encrypts: true
            )
        ],
        threats: [
            SourceLibraryThreat(
                id: "pipeline-tamper",
                name: "Pipeline tampering",
                severityLabel: "high",
                strideIds: ["tampering"],
                mitre: [SourceMitreTechnique(id: "T1565", name: "Data Manipulation", tactic: "impact")],
                controlDescriptions: ["Sign pipeline configurations"]
            )
        ]
    )

    @Test func prefixesEveryIdentifierItDeclares() throws {
        let (library, faults) = Library.build(from: source, taxonomy: taxonomy)

        let built = try #require(library)
        #expect(faults.isEmpty)
        #expect(built.label == "acme")
        #expect(built.provider == Provider(id: ProviderId("acme"), displayName: "Acme Platform"))
        #expect(built.technologies.map(\.id.value) == ["acme-cribl-stream"])
        #expect(built.threats.map(\.id.value) == ["acme-pipeline-tamper"])
    }

    @Test func leavesACatalogueThreatIdentifierBare() throws {
        let (library, _) = Library.build(from: source, taxonomy: taxonomy)

        let technology = try #require(library?.technologies.first)
        #expect(technology.threatIds.map(\.value) == ["acme-pipeline-tamper", "credential-theft"])
    }

    @Test func carriesWhatATechnologySays() throws {
        let (library, _) = Library.build(from: source, taxonomy: taxonomy)

        let technology = try #require(library?.technologies.first)
        #expect(technology.name == "Cribl Stream")
        #expect(technology.provider == ProviderId("acme"))
        #expect(technology.category == CategoryId("monitoring"))
        #expect(technology.description == "Observability pipeline")
        #expect(technology.enforcesEncryption)
    }

    @Test func carriesWhatAThreatSays() throws {
        let (library, _) = Library.build(from: source, taxonomy: taxonomy)

        let threat = try #require(library?.threats.first)
        #expect(threat.name == "Pipeline tampering")
        #expect(threat.severity == ThreatSeverity(id: "high", label: "High", rank: 3))
        #expect(threat.stride == [StrideId("tampering")])
        #expect(
            threat.mitreTechniques
                == [MitreTechnique(id: "T1565", name: "Data Manipulation", tactic: "impact")]
        )
        #expect(threat.controls.map(\.description) == ["Sign pipeline configurations"])
    }

    @Test func namesTheLabelWhenTheLibraryHasNoDisplayName() {
        let plain = LibrarySource(label: "acme")

        let (library, _) = Library.build(from: plain, taxonomy: taxonomy)

        #expect(library?.provider.displayName == "acme")
    }

    @Test func reportsAValueTheTaxonomyDoesNotHold() {
        let wrong = LibrarySource(
            label: "acme",
            technologies: [
                SourceTechnology(id: "t", name: "T", category: "observability")
            ],
            threats: [
                SourceLibraryThreat(
                    id: "x",
                    name: "X",
                    severityLabel: "severe",
                    strideIds: ["fibbing"]
                )
            ]
        )

        let (library, faults) = Library.build(from: wrong, taxonomy: taxonomy)

        #expect(library == nil)
        #expect(faults.contains(.unknownCategory(technologyId: "t", value: "observability")))
        #expect(faults.contains(.unknownSeverity(threatId: "x", value: "severe")))
        #expect(faults.contains(.unknownStride(threatId: "x", value: "fibbing")))
    }
}
