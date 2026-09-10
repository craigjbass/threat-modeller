import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// Builds a threat with a stated severity through the library path, since the
/// fixture catalogue exposes no `add` or `severity(id:)` helper. Follows the
/// pattern `LikelihoodScoringTests` and `LikelihoodFindingTests` already use.
private func endpointLibrary(threatId: String) -> Library {
    let source = LibrarySource(
        label: "endpoint",
        technologies: [
            SourceTechnology(id: "laptop", name: "Laptop", category: "compute", threatIds: [threatId])
        ],
        threats: [
            SourceLibraryThreat(id: threatId, name: "SIP Bypass", severityLabel: "critical")
        ]
    )
    let (library, faults) = Library.build(from: source, taxonomy: CatalogueFixture.taxonomy())
    precondition(faults.isEmpty, "library build faults: \(faults)")
    return library!
}

@Suite("An assessor's severity decision")
struct SeverityDecisionTests {
    private let gateway = HclControlsSource()
    private let app = TestDependencies()

    private func controls(_ block: String) -> String {
        """
        controls for "Payments" {
          threat "sip-bypass" on component "laptop" {
        \(block)
          }
        }
        """
    }

    @Test func readsTheBlockWithItsRationaleAndSources() throws {
        let text = controls("""
            severity_override "high" {
              rationale = "the exploit reads; the write path stays gated"
              sources   = ["CVE-2021-30892"]
            }
        """)
        let decision = try #require(gateway.read(text).source?.answers.first?.severityDecision)

        #expect(decision.severityId == "high")
        #expect(decision.rationale == "the exploit reads; the write path stays gated")
        #expect(decision.sources == ["CVE-2021-30892"])
    }

    @Test func refusesABlockWithNoRationale() throws {
        let text = controls("""
            severity_override "high" {
              sources = ["CVE-2021-30892"]
            }
        """)
        let errors = gateway.read(text).diagnostics.filter { $0.severity == .error }
        #expect(errors.count == 1)
        #expect(errors.first?.message.contains("rationale") == true)
    }

    @Test func writesTheBlockBackAndReadsWhatItWrote() throws {
        let text = controls("""
            severity_override "high" {
              rationale = "the exploit reads"
            }
        """)
        let source = try #require(gateway.read(text).source)
        let written = gateway.write(source)
        #expect(try #require(gateway.read(written).source) == source)
    }

    @Test func lowersTheSeverityTheScoreUses() throws {
        app.useLibraries([endpointLibrary(threatId: "sip-bypass")])
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the component was not added")
            return
        }

        app.modelStore.mutate { model in
            model.severityDecisions[
                ThreatKey(threatId: "endpoint-sip-bypass", sourceId: "component:\(componentId)")
            ] = SeverityDecision(
                severityId: "medium",
                rationale: "the exploit reads",
                sources: []
            )
        }

        let threat = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first
        )
        #expect(threat.severityId == "medium")
        #expect(threat.riskScore < 16)
    }

    /// The file's block is keyed by threat and source, and the technology-wide
    /// override is keyed by threat and technology. Both can name the same
    /// threat; the file's block wins.
    @Test func beatsATechnologyWideOverrideOnTheSameThreat() throws {
        app.useLibraries([endpointLibrary(threatId: "sip-bypass")])
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the component was not added")
            return
        }

        app.modelStore.mutate { model in
            model.severityOverrides[
                SeverityOverrideKey.forComponent(
                    technologyId: TechnologyId("endpoint-laptop"),
                    threatId: ThreatId("endpoint-sip-bypass")
                )
            ] = "low"
            model.severityDecisions[
                ThreatKey(threatId: "endpoint-sip-bypass", sourceId: "component:\(componentId)")
            ] = SeverityDecision(
                severityId: "medium",
                rationale: "the exploit reads",
                sources: []
            )
        }

        let threat = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first
        )
        #expect(threat.severityId == "medium")
    }
}
