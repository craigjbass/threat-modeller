import Testing
import ThreatModelKit
import TestSupport

@Suite("Writing down what a person learned about how often a threat happens")
struct SetLikelihoodFindingTests {
    private let app = TestDependencies()
    private let key = "component:api#credential-theft"

    private func set(
        label: String = "no campaign has used this against our stack",
        tier: String? = "research",
        prior: Int? = nil,
        rationale: String = "No public reporting names this technique against this platform.",
        sources: [String] = ["https://example.com/threat-report"]
    ) -> SetLikelihoodFindingResponse {
        app.setLikelihoodFinding().execute(
            SetLikelihoodFindingRequest(
                threatKey: key,
                label: label,
                tier: tier,
                prior: prior,
                rationale: rationale,
                sources: sources
            )
        )
    }

    private var finding: LikelihoodFinding? {
        app.modelStore.current().likelihoodFindings[ThreatKey(key)]
    }

    @Test func writesOneDownAgainstATier() {
        #expect(set() == .recorded)

        #expect(finding?.label == "no campaign has used this against our stack")
        #expect(finding?.likelihood == .research)
        #expect(finding?.rationale.isEmpty == false)
        #expect(finding?.sources == ["https://example.com/threat-report"])
    }

    @Test func writesOneDownAgainstAPrior() {
        #expect(set(tier: nil, prior: 20) == .recorded)

        #expect(finding?.likelihood.id == "20")
        #expect(finding?.likelihood.factor == 0.2)
    }

    /// A threat holds one finding, so writing a second changes the first.
    @Test func changesTheFindingAThreatAlreadyHolds() {
        _ = set(tier: "commodity")

        #expect(set(tier: "research") == .recorded)

        #expect(finding?.likelihood == .research)
    }

    // MARK: what the language refuses

    @Test func refusesAFindingThatStatesBothATierAndAPrior() {
        #expect(set(tier: "research", prior: 20) == .statesBoth)
        #expect(finding == nil)
    }

    @Test func refusesAFindingThatStatesNeither() {
        #expect(set(tier: nil, prior: nil) == .statesNeither)
        #expect(finding == nil)
    }

    @Test func refusesATierThisApplicationDoesNotHold() {
        #expect(set(tier: "occasional") == .unknownTier)
        #expect(finding == nil)
    }

    @Test func refusesAPriorOutsideItsRange() {
        #expect(set(tier: nil, prior: 101) == .priorOutOfRange)
        #expect(set(tier: nil, prior: -1) == .priorOutOfRange)
        #expect(finding == nil)
    }

    /// A finding nobody can justify is not one.
    @Test func refusesAFindingWithNoRationale() {
        #expect(set(rationale: "   ") == .noRationale)
        #expect(finding == nil)
    }

    @Test func refusesAFindingWithNoLabel() {
        #expect(set(label: "  ") == .noLabel)
        #expect(finding == nil)
    }

    // MARK: taking one off

    @Test func removesTheFinding() {
        _ = set()

        #expect(
            app.removeLikelihoodFinding().execute(
                RemoveLikelihoodFindingRequest(threatKey: key)
            ) == .removed
        )
        #expect(finding == nil)
    }

    @Test func saysSoWhenTheThreatHoldsNoFinding() {
        #expect(
            app.removeLikelihoodFinding().execute(
                RemoveLikelihoodFindingRequest(threatKey: key)
            ) == .noSuchFinding
        )
    }
}
