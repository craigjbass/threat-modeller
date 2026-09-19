import Testing
import ThreatModelKit
import TestSupport

/// Appendix B, the model inventory: what the report states about a
/// component, a flow and a zone beyond what the threat register reads.
@Suite("The report's model inventory states every attribute")
struct ExportModelAsMarkdownAttributesTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func markdown(_ model: ThreatModel) -> String {
        ExportModelAsMarkdown(
            reports: BuildThreatModelReport(
                models: InMemoryThreatModelGateway(model),
                catalogue: catalogue
            )
        ).execute(ExportModelAsMarkdownRequest()).markdown
    }

    /// GAP: a zone's, a component's and a flow's `tags` reach the parser and
    /// the writer and nothing else.
    @Test func statesAZoneSAComponentSAndAFlowSTags() {
        let model = ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential,
                    tags: ["billing", "tier-1"]
                ),
                Component(
                    id: ComponentId("c2"),
                    technologyId: TechnologyId("aws-rds"),
                    position: Point(x: 300, y: 0),
                    sensitivity: .confidential
                )
            ],
            connections: [
                Connection(
                    id: ConnectionId("f1"),
                    source: ComponentId("c1"),
                    target: ComponentId("c2"),
                    tags: ["pci"]
                )
            ],
            zones: [
                Zone(
                    id: ZoneId("z1"),
                    rect: Rect(x: -100, y: -100, width: 800, height: 700),
                    tags: ["regulated"]
                )
            ]
        )

        let text = markdown(model)

        #expect(text.contains("billing, tier-1"))
        #expect(text.contains("(tags: pci)"))
        #expect(text.contains("- Tags: regulated"))
    }

    /// GAP: `source` on a component and on a zone states what wrote it, and
    /// no report section says whether it was imported or hand-drawn.
    @Test func statesWhichElementsAnImportWroteAndWhichAPersonDrew() {
        let model = ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential,
                    source: "terraform"
                ),
                Component(
                    id: ComponentId("c2"),
                    technologyId: TechnologyId("aws-rds"),
                    position: Point(x: 300, y: 0),
                    sensitivity: .confidential
                )
            ],
            zones: [
                Zone(id: ZoneId("z1"), rect: Rect(x: -100, y: -100, width: 800, height: 700))
            ]
        )

        let text = markdown(model)

        #expect(text.contains("imported by terraform"))
        #expect(text.contains("drawn by hand"))
    }

    /// GAP: `zone.description` reaches the model and the Markdown export
    /// declares no field for it.
    @Test func statesAZoneSDescription() {
        let model = ThreatModel(
            zones: [
                Zone(
                    id: ZoneId("z1"),
                    rect: Rect(x: -100, y: -100, width: 800, height: 700),
                    description: "Holds every component that touches card data."
                )
            ]
        )

        #expect(markdown(model).contains("Holds every component that touches card data."))
    }

    /// GAP: `technology.description` on a custom technology is stored and
    /// read by no report section.
    @Test func statesACustomTechnologySDescription() {
        let model = ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("acme-widget"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential
                )
            ],
            customTechnologies: [
                CustomTechnology(
                    id: TechnologyId("acme-widget"),
                    name: "Acme Widget",
                    category: CategoryId("compute"),
                    description: "A queue this team runs itself.",
                    threatIds: []
                )
            ]
        )

        #expect(markdown(model).contains("A queue this team runs itself."))
    }

    /// GAP: `component.version` appears only inside Known vulnerabilities, so
    /// a component with a version and no CVE states its version nowhere.
    @Test func statesAComponentSVersionWithNoCve() {
        let model = ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential,
                    version: "5.2.1"
                )
            ]
        )

        let text = markdown(model)

        #expect(text.contains("5.2.1"))
        #expect(text.contains("## Known vulnerabilities") == false)
    }

    /// GAP: `threats = false` on a component drops it from the threat set
    /// and no report section says a component was silenced.
    @Test func statesAComponentWithThreatsFalseRaisesNone() {
        let model = ThreatModel(
            components: [
                Component(
                    id: ComponentId("c1"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .confidential,
                    threatsDisabled: true
                )
            ]
        )

        #expect(markdown(model).contains("raises no threats"))
    }
}
