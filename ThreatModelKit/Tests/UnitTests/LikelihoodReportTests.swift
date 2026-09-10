import Testing
import ThreatModelKit
import TestSupport

/// Builds a threat through the library path, since the fixture catalogue
/// exposes no `add` or `severity(id:)` helper. Follows the pattern
/// `LikelihoodFindingTests` uses.
private func endpointLibrary(severityLabel: String = "critical") -> Library {
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
                severityLabel: severityLabel
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

    private func aComponentRaisingTheThreat() -> String {
        app.useLibraries([endpointLibrary()])
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the component was not added")
            return ""
        }
        return componentId
    }

    @Test func statesTheTierTheReasonAndTheSources() throws {
        let componentId = aComponentRaisingTheThreat()
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

    /// Fix 1: a compensating control's sources are sub-bullets of that
    /// control's own "Compensated by" line, beside its rationale, the way
    /// the likelihood block and the severity decision already nest theirs.
    /// A source printed anywhere else leaves a reader unable to tell which
    /// control it backs.
    @Test func aCompensatingControlsSourcesSitUnderItsOwnLine() throws {
        let componentId = aComponentRaisingTheThreat()
        app.modelStore.mutate { model in
            model.compensatingControls[
                ThreatKey(threatId: "endpoint-sip-bypass", sourceId: "component:\(componentId)")
            ] = [
                CompensatingControl(
                    label: "Watched by the SIEM",
                    reducesRiskBy: 40,
                    rationale: "The one account left alerts on use.",
                    sources: ["https://example.test/adr/17"]
                )
            ]
        }

        let lines = markdown().components(separatedBy: "\n")
        let compensatedIndex = try #require(lines.firstIndex { $0.hasPrefix("- Compensated by:") })
        #expect(lines[compensatedIndex + 1] == "  - Rationale: The one account left alerts on use.")
        #expect(lines[compensatedIndex + 2] == "  - Source: https://example.test/adr/17")
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

    /// Fix 2: an assumption names no edge, so an assumed `mitigates` edge is
    /// its own bullet, naming the protector, the protected component, the
    /// threats it would answer and the reduction it would buy. It is never
    /// repeated under an assumption it has no link to.
    @Test func rendersAssumedEdgesAsTheirOwnPartNamingWhatTheyAnswer() throws {
        app.useLibraries([endpointLibrary()])
        guard case .added(let protectorId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        ), case .added(let protectedId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 100, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("a component was not added")
            return
        }

        app.modelStore.mutate { model in
            for index in model.components.indices {
                if model.components[index].id.value == protectorId {
                    model.components[index].customName = "ClearanceKit"
                } else if model.components[index].id.value == protectedId {
                    model.components[index].customName = "Store"
                }
            }
            model.assumptions = [
                SystemAssumption(label: "mdm-push", text: "MDM has not pushed the baseline yet")
            ]
            model.mitigatesEdges = [
                MitigatesEdge(
                    source: ComponentId(protectorId),
                    target: ComponentId(protectedId),
                    threatIds: [ThreatId("endpoint-sip-bypass")],
                    reducesRiskBy: 40,
                    status: .assumed
                )
            ]
        }

        let text = markdown()
        let lines = text.components(separatedBy: "\n")
        #expect(text.contains("### Assumed mitigations"))
        #expect(
            text.contains(
                "- ClearanceKit \u{2192} Store, mitigates endpoint-sip-bypass, \u{2212}40%"
            )
        )
        // The edge is not repeated under the assumption: nothing about the
        // edge appears before the "### Assumed mitigations" heading.
        let assumptionLine = try #require(lines.firstIndex { $0.hasPrefix("- mdm-push:") })
        let headingLine = try #require(lines.firstIndex(of: "### Assumed mitigations"))
        #expect(assumptionLine < headingLine)
        #expect(lines[(assumptionLine + 1)..<headingLine].contains { $0.contains("ClearanceKit") } == false)
    }

    @Test func aModelWithNoAssumptionAndNoAssumedEdgeWritesNoSection() throws {
        #expect(markdown().contains("## Assumptions") == false)
    }

    /// Finding 1: the stage floors at 1, so a threat already scoring 1 keeps
    /// that number under any tier. Gating the block on the score changing
    /// hid the tier, the rationale and the sources on exactly the threat
    /// this evidence matters most for. The block must print because a
    /// finding is recorded, not because the number moved, and the arrow is
    /// left out when the two numbers are equal.
    @Test func aThreatFlooredAtOneStillPublishesItsTierAndSources() throws {
        app.useLibraries([endpointLibrary(severityLabel: "low")])
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "public")
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
                sources: ["https://example.test/floor"]
            )
        }

        let text = markdown()
        let lines = text.components(separatedBy: "\n")
        #expect(text.contains("- Risk: low (1)"))
        // No arrow: the score before and after the stage are both 1.
        #expect(lines.contains("- Likelihood: Research"))
        #expect(text.contains("  - Rationale: every bypass was researcher-found"))
        #expect(text.contains("  - Source: https://example.test/floor"))
    }

    /// Finding 2: nothing covered the severity decision reaching the page.
    /// This is the render path Task 12's scope grew to carry.
    @Test func statesTheSeverityDecisionItsReasonAndItsSources() throws {
        let componentId = aComponentRaisingTheThreat()
        app.modelStore.mutate { model in
            model.severityDecisions[
                ThreatKey(threatId: "endpoint-sip-bypass", sourceId: "component:\(componentId)")
            ] = SeverityDecision(
                severityId: "high",
                rationale: "No public exploit lowers this below High.",
                sources: ["https://example.test/severity"]
            )
        }

        let text = markdown()
        #expect(text.contains("- Severity decided: Critical \u{2192} High"))
        #expect(text.contains("  - Rationale: No public exploit lowers this below High."))
        #expect(text.contains("  - Source: https://example.test/severity"))
    }
}
