import DiagramRendering
import Foundation
import Testing
import ThreatModelKit

@Suite("The risk over time graph")
struct RiskOverTimeChartTests {
    private func row(_ hash: String, _ day: Int, total: Int?) -> RiskHistoryRow {
        RiskHistoryRow(
            commit: SourceCommit(
                hash: hash,
                author: "Craig",
                date: Date(timeIntervalSince1970: Double(day) * 86_400)
            ),
            numbers: total.map { RiskHistoryNumbers(totalScore: $0, worstScore: $0) }
        )
    }

    @Test func drawsNothingForOneCommit() {
        #expect(RiskOverTimeChart.svg(of: [row("a", 1, total: 12)]).isEmpty)
        #expect(RiskOverTimeChart.svg(of: []).isEmpty)
    }

    @Test func drawsOneLineThroughEveryCommit() {
        let svg = RiskOverTimeChart.svg(of: [
            row("c", 3, total: 8),
            row("b", 2, total: 16),
            row("a", 1, total: 12)
        ])

        #expect(svg.hasPrefix("<svg"))
        #expect(svg.contains("</svg>"))
        #expect(svg.contains("<polyline"))
        // One dot per commit.
        #expect(svg.components(separatedBy: "<circle").count - 1 == 3)
        // The highest total is the top of the scale.
        #expect(svg.contains(">16</text>"))
    }

    @Test func breaksTheLineWhereACommitDidNotParse() {
        let svg = RiskOverTimeChart.svg(of: [
            row("c", 3, total: 8),
            row("b", 2, total: nil),
            row("a", 1, total: 12)
        ])

        // Two runs of one point each draw no line at all, and neither draws a
        // point at zero: a zero would read as "no risk".
        #expect(svg.components(separatedBy: "<circle").count - 1 == 2)
        #expect(svg.contains("<polyline") == false)
    }

    @Test func drawsTwoLinesWhereAGapSplitsTheRuns() {
        let svg = RiskOverTimeChart.svg(of: [
            row("e", 5, total: 6),
            row("d", 4, total: 7),
            row("c", 3, total: nil),
            row("b", 2, total: 16),
            row("a", 1, total: 12)
        ])

        #expect(svg.components(separatedBy: "<polyline").count - 1 == 2)
        #expect(svg.components(separatedBy: "<circle").count - 1 == 4)
    }

    @Test func namesTheOldestAndTheNewestCommit() {
        let svg = RiskOverTimeChart.svg(of: [row("bbbbbbb", 2, total: 8), row("aaaaaaa", 1, total: 12)])

        #expect(svg.contains("aaaaaaa"))
        #expect(svg.contains("bbbbbbb"))
    }
}

@Suite("The risk over time section of the report")
struct MarkdownRiskOverTimeTests {
    private func row(_ hash: String, _ day: Int, total: Int?) -> RiskHistoryRow {
        RiskHistoryRow(
            commit: SourceCommit(
                hash: hash,
                author: "Craig",
                date: Date(timeIntervalSince1970: Double(day) * 86_400)
            ),
            numbers: total.map {
                RiskHistoryNumbers(
                    totalScore: $0,
                    worstScore: 12,
                    threatCount: 4,
                    acceptedRisks: 1,
                    openAttackTrees: 1,
                    catalogueTag: "v1.0.1"
                )
            }
        )
    }

    @Test func writesNoSectionForAProjectWithOneCommit() {
        #expect(MarkdownRiskOverTime.lines([row("a", 1, total: 12)]).isEmpty)
        #expect(MarkdownRiskOverTime.lines([]).isEmpty)
    }

    @Test func writesOneRowPerCommitAndTheGraph() {
        let lines = MarkdownRiskOverTime.lines(
            [row("bbbbbbb", 2, total: 8), row("aaaaaaa", 1, total: 12)],
            picturePath: "payments-risk-over-time.svg"
        )
        let text = lines.joined(separator: "\n")

        #expect(lines.first == "## Risk over time")
        #expect(text.contains("![Total residual risk at each sampled commit](payments-risk-over-time.svg)"))
        #expect(text.contains("| 1970-01-03 | bbbbbbb | Craig | 8 | 12 | 4 | 1 | 1 | v1.0.1 |"))
    }

    @Test func statesWhenTheBoundLeftCommitsOut() {
        let text = MarkdownRiskOverTime.lines(
            [row("b", 2, total: 8), row("a", 1, total: 12)],
            truncated: true
        ).joined(separator: "\n")

        #expect(text.contains("The project holds more."))
    }

    @Test func statesACommitThatDidNotParse() {
        let text = MarkdownRiskOverTime.lines(
            [row("b", 2, total: nil), row("a", 1, total: 12)]
        ).joined(separator: "\n")

        #expect(text.contains("| did not parse |"))
    }

    @Test func aCommitAt2330UTCWritesTheDayBeforeMidnightOnEveryMachine() {
        let date = ISO8601DateFormatter().date(from: "2026-09-17T23:30:00Z")!
        #expect(MarkdownRiskOverTime.day(date) == "2026-09-17")
    }

    @Test func aCommitAt0030UTCWritesTheDayAfterMidnightOnEveryMachine() {
        let date = ISO8601DateFormatter().date(from: "2026-09-18T00:30:00Z")!
        #expect(MarkdownRiskOverTime.day(date) == "2026-09-18")
    }

    @Test func theWhatChangedHeadingAndTheRiskOverTimeRowWriteTheSameDayForOneCommit() {
        let commit = SourceCommit(
            hash: "aaaaaaa1111",
            author: "Craig",
            date: ISO8601DateFormatter().date(from: "2026-09-17T23:30:00Z")!
        )
        let riskOverTimeText = MarkdownRiskOverTime.lines([
            RiskHistoryRow(commit: commit, numbers: RiskHistoryNumbers(totalScore: 12)),
            row("b", 1, total: 8)
        ]).joined(separator: "\n")
        let whatChangedText = MarkdownWhatChanged.lines(
            RiskChange(raised: ["dos-attack on api"]),
            since: commit
        ).joined(separator: "\n")

        #expect(riskOverTimeText.contains("| 2026-09-17 | aaaaaaa"))
        #expect(whatChangedText.contains("Since aaaaaaa on 2026-09-17."))
    }
}

@Suite("The what changed section of the report")
struct MarkdownWhatChangedTests {
    private let commit = SourceCommit(
        hash: "aaaaaaa1111",
        author: "Craig",
        date: Date(timeIntervalSince1970: 86_400)
    )

    @Test func writesNoSectionWhenNothingChanged() {
        #expect(MarkdownWhatChanged.lines(RiskChange(), since: commit).isEmpty)
        #expect(MarkdownWhatChanged.lines(nil, since: commit).isEmpty)
    }

    @Test func statesEachThingThatChanged() {
        let text = MarkdownWhatChanged.lines(
            RiskChange(
                raised: ["dos-attack on api"],
                gone: ["misconfiguration on api"],
                controlsChanged: ["credential-theft on api: \"Enforce MFA\" not_implemented \u{2192} implemented"],
                acceptedAdded: ["credential-theft on api: \"Rotate keys\""],
                reviewDatesMoved: ["credential-theft on api: \"Rotate keys\" 2026-01-01 \u{2192} 2027-01-01"],
                scoreDeltas: [ElementDelta(name: "api", now: 4, then: 12)],
                catalogueMoved: "the catalogue moved from v1.0.1 to v1.1.0",
                totalNow: 4,
                totalThen: 12
            ),
            since: commit
        ).joined(separator: "\n")

        #expect(text.contains("## What changed"))
        #expect(text.contains("Since aaaaaaa on 1970-01-02. Risk is down 8 since the previous assessment."))
        #expect(text.contains("**the catalogue moved from v1.0.1 to v1.1.0.**"))
        #expect(text.contains("A score that moved with it is not a posture change."))
        #expect(text.contains("- dos-attack on api"))
        #expect(text.contains("- misconfiguration on api"))
        #expect(text.contains("| api | 12 | 4 | -8 |"))
    }
}
