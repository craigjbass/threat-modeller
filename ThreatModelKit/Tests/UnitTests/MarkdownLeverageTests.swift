import Testing
import ThreatModelKit

struct MarkdownLeverageTests {
    private let actions = [
        ReportAction(
            label: "reenable-devtool-rules",
            text: "Re-enable the dev-tool read rules",
            note: "They were disabled for friction, not for risk.",
            blockedBy: "devtool-rules-disabled",
            sources: ["https://example.com/ticket/1"],
            removes: 19,
            totalResidual: 412,
            threatsMoved: 8,
            worstBefore: 13,
            worstAfter: 5
        ),
        ReportAction(
            label: "pointless",
            text: "Buy the wrong thing",
            removes: 0,
            totalResidual: 412,
            threatsMoved: 0,
            worstBefore: 13,
            worstAfter: 13
        )
    ]

    @Test func writesATableOfWhatEachActionRemoves() {
        let lines = MarkdownLeverage.lines(actions)
        let text = lines.joined(separator: "\n")

        #expect(lines.first == "## What removes the most risk")
        #expect(text.contains("| Action | Removes | Threats moved | Worst | Blocked by |"))
        #expect(
            text.contains(
                "| Re-enable the dev-tool read rules | 19 of 412 | 8 | 13 → 5 | devtool-rules-disabled |"
            )
        )
    }

    @Test func saysLeverageDoesNotAdd() {
        let text = MarkdownLeverage.lines(actions).joined(separator: "\n")

        // Without this a reader adds the top rows and plans against a number
        // the model never produced.
        #expect(text.contains("do not remove the sum of their leverage"))
        #expect(text.contains("the stronger reduction wins, never the sum"))
    }

    @Test func statesAnActionThatRemovesNothing() {
        let text = MarkdownLeverage.lines(actions).joined(separator: "\n")

        #expect(text.contains("| Buy the wrong thing | removes nothing at today's posture | 0 | 13 → 13 | — |"))
    }

    @Test func writesTheNoteAndTheSourcesUnderTheTable() {
        let text = MarkdownLeverage.lines(actions).joined(separator: "\n")

        #expect(text.contains("- Re-enable the dev-tool read rules"))
        #expect(text.contains("  - They were disabled for friction, not for risk."))
        #expect(text.contains("  - Source: [https://example.com/ticket/1](https://example.com/ticket/1)"))
    }

    @Test func writesNothingForAModelDeclaringNoAction() {
        #expect(MarkdownLeverage.lines([]).isEmpty)
    }
}
