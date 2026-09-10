import Testing
import ThreatModelKit
import TestSupport

/// Builds a threat through the library path, since the fixture catalogue
/// exposes no `add` or `severity(id:)` helper. Follows the pattern
/// `LikelihoodFindingTests` uses.
private func endpointLibrary() -> Library {
    let source = LibrarySource(
        label: "endpoint",
        technologies: [
            SourceTechnology(
                id: "laptop",
                name: "Laptop",
                category: "compute",
                threatIds: ["sip-bypass"]
            )
        ],
        threats: [
            SourceLibraryThreat(
                id: "sip-bypass",
                name: "SIP Bypass",
                severityLabel: "critical"
            )
        ]
    )
    let (library, faults) = Library.build(from: source, taxonomy: CatalogueFixture.taxonomy())
    precondition(faults.isEmpty, "library build faults: \(faults)")
    return library!
}

@Suite("What the report says about likelihood and assumptions")
struct LikelihoodReportTests {
    private let app = TestDependencies()

    private func markdown() -> String {
        app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
    }

    @Test func statesTheTierTheReasonAndTheSources() throws {
        app.useLibraries([endpointLibrary()])
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the component was not added")
            return
        }
        app.modelStore.mutate { model in
            model.likelihoodFindings[
                ThreatKey(threatId: "endpoint-sip-bypass", sourceId: "component:\(componentId)")
            ] = LikelihoodFinding(
                label: "no in-the-wild use",
                likelihood: .research,
                rationale: "every bypass was researcher-found",
                sources: ["https://example.test/a"]
            )
        }

        let text = markdown()
        #expect(text.contains("- Likelihood: Research (16 \u{2192} 4)"))
        #expect(text.contains("  - Rationale: every bypass was researcher-found"))
        #expect(text.contains("  - Source: https://example.test/a"))
    }

    @Test func listsTheAssumptionsAndTheirEdges() throws {
        app.modelStore.mutate { model in
            model.assumptions = [
                SystemAssumption(
                    label: "mdm-push",
                    text: "MDM has not pushed the baseline yet",
                    owner: "platform team"
                )
            ]
        }

        let text = markdown()
        #expect(text.contains("## Assumptions"))
        #expect(text.contains("- mdm-push: MDM has not pushed the baseline yet (platform team)"))
    }

    @Test func aModelWithNoAssumptionWritesNoSection() throws {
        #expect(markdown().contains("## Assumptions") == false)
    }
}
