import Testing
import ThreatModelKit

struct MarkdownRecommendationsTests {
    private func recommendation(_ text: String, _ score: Int, on element: String) -> ReportRecommendation {
        ReportRecommendation(
            text: text,
            note: nil,
            threatName: "t",
            sourceName: element,
            riskScore: score
        )
    }

    /// `RecommendationsReport` decides the order (see
    /// `RecommendationsSectionTests.theBuiltListOrdersByTheRiskItAnswersNotByTheElement`).
    /// This writer prints the list it is given, in that order, and does not
    /// sort it again.
    @Test func printsTheListInTheOrderItIsGivenWithoutSortingIt() throws {
        let text = MarkdownRecommendations.lines([
            recommendation("small", 3, on: "Alpha"),
            recommendation("large", 13, on: "Beta"),
            recommendation("middle", 8, on: "Alpha")
        ]).joined(separator: "\n")

        let small = try #require(text.range(of: "small"))
        let large = try #require(text.range(of: "large"))
        let middle = try #require(text.range(of: "middle"))

        #expect(small.lowerBound < large.lowerBound)
        #expect(large.lowerBound < middle.lowerBound)
    }

    @Test func endsWithABlankLine() {
        let lines = MarkdownRecommendations.lines([recommendation("small", 3, on: "Alpha")])

        #expect(lines.last == "")
    }
}
