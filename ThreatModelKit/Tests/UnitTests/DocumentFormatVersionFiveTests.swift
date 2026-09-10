import Testing
import Foundation
import ThreatModelKit
import FileGateways
import TestSupport

/// Builds a threat through the library path, since the fixture catalogue
/// exposes no `add` helper. Follows the pattern `LikelihoodFindingTests` and
/// `SeverityDecisionTests` already use.
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

struct DocumentFormatVersionFiveTests {
    private func model() -> ThreatModel {
        ThreatModel(
            name: "S",
            likelihoodFindings: [
                ThreatKey(threatId: "credential-theft", sourceId: "component:store"):
                    LikelihoodFinding(
                        label: "no in-the-wild use",
                        likelihood: .research,
                        rationale: "every bypass was researcher-found",
                        sources: ["CVE-2021-30892"]
                    )
            ],
            severityDecisions: [
                ThreatKey(threatId: "credential-theft", sourceId: "component:store"):
                    SeverityDecision(
                        severityId: "high",
                        rationale: "the exploit reads; the write path stays gated",
                        sources: ["https://example.internal/adr/9"]
                    )
            ],
            assumptions: [
                SystemAssumption(label: "network", text: "the VPN is trusted", owner: "platform team"),
                SystemAssumption(label: "physical", text: "the office is access-controlled")
            ],
            riskTolerance: .medium
        )
    }

    @Test func aRoundTripKeepsEveryNewValue() throws {
        let data = try ThreatModelCodec().encode(model())
        let read = try ThreatModelCodec().decode(data)

        let key = ThreatKey(threatId: "credential-theft", sourceId: "component:store")

        let finding = try #require(read.likelihoodFindings[key])
        #expect(finding.label == "no in-the-wild use")
        #expect(finding.likelihood.id == "research")
        #expect(finding.rationale == "every bypass was researcher-found")
        #expect(finding.sources == ["CVE-2021-30892"])

        let decision = try #require(read.severityDecisions[key])
        #expect(decision.severityId == "high")
        #expect(decision.rationale == "the exploit reads; the write path stays gated")
        #expect(decision.sources == ["https://example.internal/adr/9"])

        #expect(read.assumptions.count == 2)
        #expect(read.assumptions.first?.label == "network")
        #expect(read.assumptions.first?.text == "the VPN is trusted")
        #expect(read.assumptions.first?.owner == "platform team")
        #expect(read.assumptions.last?.label == "physical")
        #expect(read.assumptions.last?.text == "the office is access-controlled")
        #expect(read.assumptions.last?.owner == nil)

        #expect(read.riskTolerance == .medium)
    }

    /// A document that holds none of the four round trips to the same empty
    /// state, and a nil risk tolerance writes no key at all: the same
    /// convention the mitigates edge's `status` already follows.
    @Test func aDocumentHoldingNoneOfThemRoundTripsUnchangedAndWritesNoToleranceKey() throws {
        let empty = ThreatModel(name: "S")

        let data = try ThreatModelCodec().encode(empty)
        let text = try #require(String(data: data, encoding: .utf8))
        #expect(text.contains("\"riskTolerance\"") == false)

        let read = try ThreatModelCodec().decode(data)
        #expect(read.likelihoodFindings.isEmpty)
        #expect(read.severityDecisions.isEmpty)
        #expect(read.assumptions.isEmpty)
        #expect(read.riskTolerance == nil)
    }

    @Test func theFormatVersionIsFive() throws {
        let data = try ThreatModelCodec().encode(model())
        let text = try #require(String(data: data, encoding: .utf8))
        #expect(text.contains("\"formatVersion\" : 5"))
    }

    /// A file written before this change carries none of the four keys, and
    /// still opens: every value it does not hold takes its default.
    @Test func aVersionFourDocumentStillReadsWithNoneOfTheFour() throws {
        let text = """
        {
          "formatVersion" : 4,
          "name" : "S",
          "createdAt" : "1970-01-01T00:00:00Z",
          "updatedAt" : "1970-01-01T00:00:00Z",
          "components" : [],
          "connections" : [],
          "zones" : [],
          "customTechnologies" : [],
          "severityOverrides" : {},
          "implementedControls" : [],
          "pathwayMitigations" : { "isMasterEnabled" : false, "configs" : {} }
        }
        """
        let read = try ThreatModelCodec().decode(Data(text.utf8))
        #expect(read.name == "S")
        #expect(read.likelihoodFindings.isEmpty)
        #expect(read.severityDecisions.isEmpty)
        #expect(read.assumptions.isEmpty)
        #expect(read.riskTolerance == nil)
    }

    /// D2: the score `AssessThreatModel` reports for a threat carrying a
    /// likelihood finding and a severity decision is the same after a save
    /// and a load as it was before. A codec that dropped either would change
    /// the number, and the reason for it, the next time the document opens.
    @Test func theReportedScoreSurvivesASaveAndALoad() throws {
        let app = TestDependencies()
        app.useLibraries([endpointLibrary(threatId: "sip-bypass")])
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "endpoint-laptop", x: 0, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the component was not added")
            return
        }
        let key = ThreatKey(threatId: "endpoint-sip-bypass", sourceId: "component:\(componentId)")

        app.modelStore.mutate { model in
            model.likelihoodFindings[key] = LikelihoodFinding(
                label: "no in-the-wild use",
                likelihood: .research,
                rationale: "every bypass was researcher-found",
                sources: ["CVE-2021-30892"]
            )
            model.severityDecisions[key] = SeverityDecision(
                severityId: "high",
                rationale: "the write path stays gated",
                sources: ["https://example.internal/adr/9"]
            )
        }

        let before = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first
        )

        let data = try ThreatModelCodec().encode(app.modelStore.current())
        let reloaded = try ThreatModelCodec().decode(data)
        app.modelStore.save(reloaded)

        let after = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats.first
        )

        #expect(after.riskScore == before.riskScore)
        #expect(after.likelihoodId == before.likelihoodId)
        #expect(after.likelihoodRationale == before.likelihoodRationale)
        #expect(after.likelihoodSources == before.likelihoodSources)
        #expect(after.severityDecision == before.severityDecision)
        #expect(before.severityDecision != nil)
        #expect(before.likelihoodRationale != nil)
    }
}
