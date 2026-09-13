import Testing
import ThreatModelKit

struct MarkdownAttackPathsTests {
    private func hop(
        _ name: String,
        flow: String? = nil,
        threat: String? = nil,
        score: Int = 0,
        reducedBy: [String] = []
    ) -> ReportAttackPathHop {
        ReportAttackPathHop(
            componentName: name,
            flowKindLabel: flow,
            worstThreatName: threat,
            riskScore: score,
            reducedBy: reducedBy
        )
    }

    @Test func writesThePrefixOnceAndATablePerPath() {
        let text = MarkdownAttackPaths.lines(
            [
                ReportAttackPath(
                    startName: "Internet",
                    endName: "Secrets store",
                    hops: [
                        hop("Build pipeline", flow: "Network", threat: "Package substitution", score: 13),
                        hop("Secrets store", flow: "Local IPC", threat: "Credential theft", score: 9, reducedBy: ["Touch ID gate"])
                    ],
                    worstScore: 13,
                    likelihoodLabel: "Commodity"
                )
            ],
            prefix: [hop("Internet"), hop("ClearanceKit GUI")]
        ).joined(separator: "\n")

        #expect(text.hasPrefix("## Attack paths"))
        #expect(text.contains("Every path below starts at Internet \u{2192} ClearanceKit GUI."))
        #expect(text.contains("### 1. Internet \u{2192} Secrets store \u{2014} worst 13, Commodity"))
        #expect(text.contains("| Hop | Flow | Worst threat | Score | Reduced by |"))
        #expect(text.contains("| Build pipeline | Network | Package substitution | 13 | nothing reduces this hop |"))
        #expect(text.contains("| Secrets store | Local IPC | Credential theft | 9 | Touch ID gate |"))
    }

    @Test func writesNoPrefixLineWhenThePathsShareNoStart() {
        let text = MarkdownAttackPaths.lines(
            [ReportAttackPath(startName: "A", endName: "B", hops: [hop("A"), hop("B")], worstScore: 3)],
            prefix: []
        ).joined(separator: "\n")

        #expect(text.contains("Every path below starts") == false)
        #expect(text.contains("### 1. A \u{2192} B \u{2014} worst 3"))
    }

    @Test func writesTheFallbackRowWhenAHopHasNoFlowAndNoThreat() {
        let text = MarkdownAttackPaths.lines(
            [ReportAttackPath(startName: "A", endName: "B", hops: [hop("A", score: 5)], worstScore: 5)],
            prefix: []
        ).joined(separator: "\n")

        #expect(text.contains("| A | \u{2014} | none | 5 | nothing reduces this hop |"))
    }

    @Test func escapesAPipeInAHopName() {
        let text = MarkdownAttackPaths.lines(
            [ReportAttackPath(startName: "A|B", endName: "C", hops: [hop("A|B", score: 2)], worstScore: 2)],
            prefix: []
        ).joined(separator: "\n")

        #expect(text.contains("| A\\|B | \u{2014} | none | 2 | nothing reduces this hop |"))
    }

    @Test func writesNoneWhenTheTraceFoundNothing() {
        let text = MarkdownAttackPaths.lines([], prefix: []).joined(separator: "\n")

        #expect(text.contains("## Attack paths"))
        #expect(text.contains("None."))
    }

    @Test func writesTheDroppedPathsAsAnAppendix() {
        let text = MarkdownAttackPaths.appendixLines(
            [ReportAttackPathSummary(startName: "Internet", endName: "Queue", worstScore: 8)],
            beyond: 0
        ).joined(separator: "\n")

        #expect(text.hasPrefix("## Appendix C \u{2014} Attack paths not listed"))
        #expect(text.contains("- Internet \u{2192} Queue, worst 8"))
        #expect(text.contains("names no further path") == false)
    }

    @Test func saysHowManyPathsNotEvenTheAppendixNames() {
        let text = MarkdownAttackPaths.appendixLines(
            [ReportAttackPathSummary(startName: "Internet", endName: "Queue", worstScore: 8)],
            beyond: 7
        ).joined(separator: "\n")

        #expect(text.contains("The trace found 7 further paths this report names nowhere."))
    }

    @Test func writesTheAppendixForTheOverflowAloneWhenNothingWasListed() {
        let text = MarkdownAttackPaths.appendixLines([], beyond: 7).joined(separator: "\n")

        #expect(text.contains("The trace found 7 further paths this report names nowhere."))
    }

    @Test func writesNoAppendixWhenNothingWasDropped() {
        #expect(MarkdownAttackPaths.appendixLines([], beyond: 0).isEmpty)
    }
}
