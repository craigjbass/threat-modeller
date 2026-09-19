import Testing
import ThreatModelKit
import TestSupport

/// What the report states that the model alone did not: the attributes
/// group E of the audit found nothing downstream read.
@Suite("The report states the attributes nothing reads today")
struct BuildThreatModelReportAttributesTests {
    private let catalogue = CatalogueFixture.catalogue()

    /// GAP: a governance `action` whose label no `mitigates` edge gives text
    /// to is dropped, so its owner, effort and due date reach no section.
    @Test func aGovernanceActionNoEdgeNamesReachesTheLeverageTable() {
        let model = ThreatModel(
            actionWork: [
                "rotate-the-signing-key": PlannedWork(
                    label: "rotate-the-signing-key",
                    owner: "Head of Platform",
                    status: .inProgress
                )
            ]
        )

        let report = BuildThreatModelReport(
            models: InMemoryThreatModelGateway(model),
            catalogue: catalogue
        ).execute(BuildThreatModelReportRequest()).report

        let orphan = report.actions.first { $0.label == "rotate-the-signing-key" }
        #expect(orphan != nil)
        #expect(orphan?.governance?.contains("Head of Platform") == true)

        let markdown = ExportModelAsMarkdown(
            reports: BuildThreatModelReport(
                models: InMemoryThreatModelGateway(model),
                catalogue: catalogue
            )
        ).execute(ExportModelAsMarkdownRequest()).markdown
        #expect(markdown.contains("rotate-the-signing-key"))
    }

    /// GAP: a library threat's `mitre` block states a name and a tactic, and
    /// the report takes the name from the synced bundle instead, so a
    /// machine that has not synchronised prints bare ids.
    @Test func usesTheLibrarySOwnMitreNameWhenTheMachineHasNotSynchronised() throws {
        let model = ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential
                )
            ]
        )

        // No `mitre:` argument: this machine has not synchronised the bundle.
        let report = BuildThreatModelReport(
            models: InMemoryThreatModelGateway(model),
            catalogue: catalogue
        ).execute(BuildThreatModelReportRequest()).report

        let threat = try #require(report.threats.first { $0.threatId == "credential-theft" })
        #expect(threat.mitreTechniqueNames["T1552"] == "Unsecured Credentials (Credential Access)")
    }

    /// Acceptance: a model stating `tags`, `source`, a component version
    /// with no CVE, `threats = false`, a control note, a planned work
    /// acceptance and a library override, read through one report.
    @Test func theReportNamesEveryAttributeTheModelStates() throws {
        let recommendationText = "Rotate credentials on a schedule"
        let key = ThreatKey(threatId: "credential-theft", sourceId: "component:c1")

        let store = LibraryStore()
        store.set([
            Library(
                label: "acme-library",
                provider: Provider(id: ProviderId("acme"), displayName: "Acme"),
                technologies: [],
                threats: [],
                overrides: [
                    ThreatId("credential-theft"): ThreatOverride(
                        libraryLabel: "acme-library",
                        severity: CatalogueFixture.high
                    )
                ]
            )
        ])
        let merged = MergedCatalogue(base: catalogue, store: store)

        let model = ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential,
                    tags: ["billing"],
                    version: "5.2.1",
                    source: "terraform"
                ),
                Component(
                    id: ComponentId("c2"),
                    technologyId: TechnologyId("aws-rds"),
                    position: Point(x: 300, y: 0),
                    sensitivity: .confidential,
                    threatsDisabled: true
                )
            ],
            recommendations: [
                key: [Recommendation(text: recommendationText)]
            ],
            controlNotes: [
                ControlIdentity.componentControl(
                    componentId: ComponentId("c1"),
                    threatId: ThreatId("credential-theft"),
                    description: "Enforce IMDSv2 to block SSRF-based credential theft",
                    isTechnologySpecific: true
                ): "Rotated by the platform team every quarter."
            ],
            plannedWork: [
                key: [
                    PlannedWork(
                        label: recommendationText,
                        acceptance: "The audit log shows a rotation inside the last 30 days."
                    )
                ]
            ]
        )

        let markdown = ExportModelAsMarkdown(
            reports: BuildThreatModelReport(
                models: InMemoryThreatModelGateway(model),
                catalogue: merged
            )
        ).execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("billing"))
        #expect(markdown.contains("imported by terraform"))
        #expect(markdown.contains("5.2.1"))
        #expect(markdown.contains("raises no threats"))
        #expect(markdown.contains("Rotated by the platform team every quarter."))
        #expect(markdown.contains("The audit log shows a rotation inside the last 30 days."))
        #expect(markdown.contains("Changed by the library: acme-library (severity)"))
    }
}
