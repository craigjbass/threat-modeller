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

    @Test func ordersByTheRiskItAnswersNotByTheElement() throws {
        let text = MarkdownRecommendations.lines([
            recommendation("small", 3, on: "Alpha"),
            recommendation("large", 13, on: "Beta"),
            recommendation("middle", 8, on: "Alpha")
        ]).joined(separator: "\n")

        let large = try #require(text.range(of: "large"))
        let middle = try #require(text.range(of: "middle"))
        let small = try #require(text.range(of: "small"))

        #expect(large.lowerBound < middle.lowerBound)
        #expect(middle.lowerBound < small.lowerBound)
    }
}
