import Testing
import ThreatModelKit

struct MarkdownMethodologyTests {
    private let methodology = ReportMethodology(
        levelThresholds: [
            ReportLevelThreshold(label: "Low", lowest: 1, highest: 3),
            ReportLevelThreshold(label: "Critical", lowest: 12, highest: 16)
        ],
        controlCapPercent: 70,
        likelihoodTiers: [ReportCount(label: "Targeted", count: 60)],
        zoneReductions: [ReportCount(label: "Private", count: 30)],
        toleranceLabel: "Medium"
    )

    @Test func statesTheArithmeticInTheOrderTheStagesRun() {
        let text = MarkdownMethodology.lines(methodology).joined(separator: "\n")

        #expect(text.hasPrefix("## Methodology"))
        #expect(text.contains("severity rank multiplied by the data sensitivity rank"))
        #expect(text.contains("| Low | 1 | 3 |"))
        #expect(text.contains("| Critical | 12 | 16 |"))
        #expect(text.contains("Private reduces the risk of what it holds by 30%."))
        #expect(text.contains("capped at 70%"))
        #expect(text.contains("Targeted 60%"))
        #expect(text.contains("The project's risk tolerance is Medium."))
        #expect(text.contains("A score never falls below 1."))
    }

    @Test func omitsTheZoneLineWhenNoZoneReducesRisk() {
        let text = MarkdownMethodology.lines(
            ReportMethodology(
                levelThresholds: [ReportLevelThreshold(label: "Low", lowest: 1, highest: 3)],
                controlCapPercent: 70,
                likelihoodTiers: [],
                zoneReductions: [],
                toleranceLabel: "Low"
            )
        ).joined(separator: "\n")

        #expect(text.contains("reduces the risk of what it holds") == false)
    }

    @Test func writesTheDiagramLegend() {
        let text = MarkdownMethodology.lines(methodology).joined(separator: "\n")

        #expect(text.contains("### Diagram legend"))
        #expect(text.contains("| Red, orange, yellow, green |"))
        #expect(text.contains("| Purple dashed line |"))
        #expect(text.contains("| Dashed guard marker |"))
        #expect(text.contains("| Badge on an element |"))
    }
}
