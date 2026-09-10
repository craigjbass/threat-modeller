import Testing
import ThreatModelKit
import TestSupport

struct RecommendationsSectionTests {
    private func threat(_ id: String, _ source: String, _ score: Int) -> ReportThreat {
        ReportThreat(
            threatId: id,
            name: id.capitalized,
            description: "",
            severityLabel: "High",
            riskScore: score,
            riskLevel: "high",
            strideLabels: [],
            mitreTechniqueIds: [],
            sourceName: source,
            sourceKind: "Component",
            sourceId: "component:\(source)",
            controls: [],
            pathwayMitigationLabels: []
        )
    }

    @Test func aRecommendationCarriesItsThreatAndItsScore() {
        let built = RecommendationsReport.build(
            threats: [threat("credential-theft", "store", 8)],
            recommendations: [
                ThreatKey(threatId: "credential-theft", sourceId: "component:store"):
                    [Recommendation(text: "Deny reads of /dev/rdisk**", note: "An endpoint rule.")]
            ]
        )
        #expect(built.count == 1)
        #expect(built.first?.text == "Deny reads of /dev/rdisk**")
        #expect(built.first?.threatName == "Credential-Theft")
        #expect(built.first?.riskScore == 8)
    }

    @Test func theWorstThreatComesFirst() {
        let built = RecommendationsReport.build(
            threats: [threat("a", "one", 4), threat("b", "two", 12)],
            recommendations: [
                ThreatKey(threatId: "a", sourceId: "component:one"): [Recommendation(text: "first")],
                ThreatKey(threatId: "b", sourceId: "component:two"): [Recommendation(text: "second")]
            ]
        )
        #expect(built.map(\.text) == ["second", "first"])
    }

    @Test func theMarkdownWritesNothingWhenThereAreNone() {
        #expect(MarkdownRecommendations.lines([]).isEmpty)
    }

    @Test func theMarkdownNamesTheThreatAndPrintsTheNote() {
        let lines = MarkdownRecommendations.lines([
            ReportRecommendation(
                text: "Deny reads of /dev/rdisk**",
                note: "An endpoint rule.",
                threatName: "Raw device read",
                sourceName: "store",
                riskScore: 12
            )
        ])
        #expect(lines.first == "## Recommendations")
        #expect(lines.contains("### store"))
        #expect(lines.contains("- Deny reads of /dev/rdisk**"))
        #expect(lines.contains("  - Raw device read, risk 12"))
        #expect(lines.contains("  - An endpoint rule."))
    }

    @Test func recommendationsAreGroupedBySourceOrderedByTheGroupsWorst() throws {
        let lines = MarkdownRecommendations.lines([
            ReportRecommendation(text: "b", note: nil, threatName: "B", sourceName: "store", riskScore: 8),
            ReportRecommendation(text: "a", note: nil, threatName: "A", sourceName: "guard", riskScore: 20),
            ReportRecommendation(text: "c", note: nil, threatName: "C", sourceName: "store", riskScore: 12)
        ])

        // "guard" carries the worst recommendation (20), so its group comes
        // first, ahead of "store" (worst 12), even though "store" appears
        // first in the input.
        let guardHeading = try #require(lines.firstIndex(of: "### guard"))
        let storeHeading = try #require(lines.firstIndex(of: "### store"))
        #expect(guardHeading < storeHeading)

        // Inside "store", the worse recommendation (c, 12) comes before the
        // lesser one (b, 8).
        let cIndex = try #require(lines.firstIndex(of: "- c"))
        let bIndex = try #require(lines.firstIndex(of: "- b"))
        #expect(cIndex < bIndex)
    }

    @Test func theDependencySectionNamesTheProtectorAndWhatIsUnanswered() {
        let lines = MarkdownProtectionDependencies.lines([
            ReportProtectionDependency(
                protectorName: "ClearanceKit",
                protects: ["credential-theft on store"],
                unanswered: [
                    ReportUnansweredThreat(name: "Tampering", riskScore: 12, riskLevel: "critical")
                ]
            )
        ])
        #expect(lines.first == "## Protection dependencies")
        #expect(lines.contains("### ClearanceKit"))
        #expect(lines.contains("- Answers: credential-theft on store"))
        #expect(lines.contains("- Unanswered on this component: Tampering (critical, 12)"))
    }

    @Test func theDependencySectionSaysWhenNothingIsUnanswered() {
        let lines = MarkdownProtectionDependencies.lines([
            ReportProtectionDependency(
                protectorName: "ClearanceKit",
                protects: ["credential-theft on store"],
                unanswered: []
            )
        ])
        #expect(lines.contains("### ClearanceKit"))
        #expect(lines.contains("- Nothing on this component is unanswered."))
    }

    @Test func twoRecommendationsOnOneThreatBothAppear() {
        let built = RecommendationsReport.build(
            threats: [threat("credential-theft", "store", 8)],
            recommendations: [
                ThreatKey(threatId: "credential-theft", sourceId: "component:store"): [
                    Recommendation(text: "first"),
                    Recommendation(text: "second")
                ]
            ]
        )
        #expect(built.count == 2)
        #expect(built.map(\.text).sorted() == ["first", "second"])
        #expect(built.allSatisfy { $0.threatName == "Credential-Theft" })
        #expect(built.allSatisfy { $0.riskScore == 8 })
    }

    @Test func recommendationsAtTheSameScoreSortByText() {
        let built = RecommendationsReport.build(
            threats: [threat("a", "one", 8), threat("b", "two", 8)],
            recommendations: [
                ThreatKey(threatId: "a", sourceId: "component:one"): [Recommendation(text: "second")],
                ThreatKey(threatId: "b", sourceId: "component:two"): [Recommendation(text: "first")]
            ]
        )
        #expect(built.map(\.text) == ["first", "second"])
    }
}
