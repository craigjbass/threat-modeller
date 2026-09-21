import Foundation
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The four things `docs/LANGUAGE.md` states that the interface could not
/// reach. Each of these goes through the session, the way a control does.
@MainActor
struct ReachingEveryFeatureTests {
    private func aModel() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        return session
    }

    // MARK: assumptions

    @Test func writesAnAssumptionAndShowsIt() {
        let session = aModel()

        session.setAssumption(label: "network-segmented", text: "It is.", owner: "platform")

        #expect(session.canvas.assumptions.count == 1)
        #expect(session.canvas.assumptions.first?.label == "network-segmented")
        #expect(session.errorMessage == nil)
    }

    @Test func saysSoWhenAnAssumptionSaysNothing() {
        let session = aModel()

        session.setAssumption(label: "network-segmented", text: "   ", owner: nil)

        #expect(session.canvas.assumptions.isEmpty)
        #expect(session.errorMessage == "An assumption needs to say something.")
    }

    @Test func takesAnAssumptionBackOff() {
        let session = aModel()
        session.setAssumption(label: "network-segmented", text: "It is.", owner: nil)

        session.removeAssumption(label: "network-segmented")

        #expect(session.canvas.assumptions.isEmpty)
    }

    // MARK: mitigates

    @Test func writesAMitigatesEdgeAndShowsIt() throws {
        let session = aModel()
        let ids = session.canvas.components.map(\.id)
        let (guardId, storeId) = (try #require(ids.first), try #require(ids.last))

        session.setMitigatesEdge(
            from: guardId,
            to: storeId,
            status: "proposed"
        )

        #expect(session.canvas.mitigations.count == 1)
        #expect(session.canvas.mitigations.first?.status == "proposed")
        #expect(session.errorMessage == nil)
    }

    /// The mitigates sheet writes `note`, `blocked_by` and `sources` on an
    /// assumed edge's recommendation, and the canvas reads all three back, so
    /// opening the sheet again shows what the edge holds.
    @Test func writesTheRecommendationsNoteBlockerAndSourcesOnAnEdge() throws {
        let session = aModel()
        let ids = session.canvas.components.map(\.id)
        let (guardId, storeId) = (try #require(ids.first), try #require(ids.last))
        session.setAssumption(label: "the-budget", text: "The team has none.", owner: nil)

        session.setMitigatesEdge(
            from: guardId,
            to: storeId,
            status: "proposed",
            actionLabel: "adopt-the-guard",
            actionText: "Adopt the guard",
            actionNote: "The platform team owns it.",
            blockedBy: "the-budget",
            sources: ["https://example.test/plan"]
        )

        #expect(session.errorMessage == nil)
        let edge = try #require(session.canvas.mitigations.first)
        #expect(edge.actionLabel == "adopt-the-guard")
        #expect(edge.actionText == "Adopt the guard")
        #expect(edge.actionNote == "The platform team owns it.")
        #expect(edge.actionBlockedBy == "the-budget")
        #expect(edge.actionSources == ["https://example.test/plan"])
    }

    @Test func saysSoWhenAMitigatesEdgeStatesAStatusTheLanguageDoesNotRead() throws {
        let session = aModel()
        let ids = session.canvas.components.map(\.id)

        session.setMitigatesEdge(
            from: try #require(ids.first),
            to: try #require(ids.last),
            status: "adopted"
        )

        #expect(session.canvas.mitigations.isEmpty)
        #expect(session.errorMessage == "A mitigates edge is \"live\" or \"proposed\".")
    }

    @Test func takesAMitigatesEdgeBackOff() throws {
        let session = aModel()
        let ids = session.canvas.components.map(\.id)
        let (guardId, storeId) = (try #require(ids.first), try #require(ids.last))
        session.setMitigatesEdge(
            from: guardId,
            to: storeId,
            status: "proposed"
        )

        session.removeMitigatesEdge(from: guardId, to: storeId)

        #expect(session.canvas.mitigations.isEmpty)
    }

    // MARK: likelihood

    @Test func writesALikelihoodFindingOnAThreat() throws {
        let session = aModel()
        let threat = try #require(session.threats.first)
        let before = threat.riskScore

        session.setLikelihoodFinding(
            threatKey: threat.threatKey,
            label: "no campaign has used this",
            tier: "research",
            prior: nil,
            rationale: "No public reporting names it.",
            sources: []
        )

        #expect(session.errorMessage == nil)
        // A finding multiplies the score rather than answering the threat, so
        // the threat is still there and scores lower.
        let after = try #require(session.threats.first { $0.threatKey == threat.threatKey })
        #expect(after.riskScore < before)
    }

    @Test func saysSoWhenAFindingStatesATierAndAPrior() throws {
        let session = aModel()
        let threat = try #require(session.threats.first)

        session.setLikelihoodFinding(
            threatKey: threat.threatKey,
            label: "both",
            tier: "research",
            prior: 20,
            rationale: "Why.",
            sources: []
        )

        #expect(session.errorMessage == "A finding states a tier or a prior; it states one.")
    }
}
