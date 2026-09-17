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
        #expect(lines.contains("- Deny reads of /dev/rdisk**"))
        #expect(lines.contains("  - Raw device read on store, risk 12"))
        #expect(lines.contains("  - An endpoint rule."))
    }

    /// Finding 3: nothing covered a recommendation's sources reaching the
    /// page.
    @Test func theMarkdownPrintsARecommendationsSources() {
        let lines = MarkdownRecommendations.lines([
            ReportRecommendation(
                text: "Deny reads of /dev/rdisk**",
                note: nil,
                threatName: "Raw device read",
                sourceName: "store",
                riskScore: 12,
                sources: ["https://example.test/rec"]
            )
        ])
        #expect(lines.contains("  - Source: [https://example.test/rec](https://example.test/rec)"))
    }

    @Test func theMarkdownPrintsNoSourceLineWhenTheRecommendationNamesNone() {
        let lines = MarkdownRecommendations.lines([
            ReportRecommendation(
                text: "Deny reads of /dev/rdisk**",
                note: nil,
                threatName: "Raw device read",
                sourceName: "store",
                riskScore: 12
            )
        ])
        #expect(lines.contains { $0.hasPrefix("  - Source:") } == false)
    }

    /// `RecommendationsReport.build` decides the order, not the writer. See
    /// `theBuiltListOrdersByTheRiskItAnswersNotByTheElement` below.
    @Test func theBuiltListOrdersByTheRiskItAnswersNotByTheElement() throws {
        let built = RecommendationsReport.build(
            threats: [
                threat("a", "guard", 20),
                threat("b", "store", 8),
                threat("c", "store", 12)
            ],
            recommendations: [
                ThreatKey(threatId: "a", sourceId: "component:guard"): [Recommendation(text: "a")],
                ThreatKey(threatId: "b", sourceId: "component:store"): [Recommendation(text: "b")],
                ThreatKey(threatId: "c", sourceId: "component:store"): [Recommendation(text: "c")]
            ]
        )

        // The worst recommendation (a, 20) comes first, then c (12), then b (8),
        // regardless of the element it answers.
        #expect(built.map(\.text) == ["a", "c", "b"])
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

    // MARK: a picture of each control

    @Test func theDependencySectionShowsThePictureOfEachControl() throws {
        let lines = MarkdownProtectionDependencies.lines(
            [
                ReportProtectionDependency(
                    protectorName: "ClearanceKit",
                    protects: ["credential-theft on store"],
                    protectorId: "ck"
                )
            ],
            pictures: ["ck": "model-control-1.svg"]
        )

        let heading = try #require(lines.firstIndex(of: "### ClearanceKit"))
        let picture = try #require(
            lines.firstIndex(of: "![What ClearanceKit protects](model-control-1.svg)")
        )
        let bullet = try #require(lines.firstIndex(of: "- Answers: credential-theft on store"))

        #expect(heading < picture)
        #expect(picture < bullet)
    }

    @Test func theDependencySectionShowsNoPictureWhenNoneWasDrawn() {
        let lines = MarkdownProtectionDependencies.lines([
            ReportProtectionDependency(protectorName: "ClearanceKit", protectorId: "ck")
        ])

        #expect(lines.contains { $0.hasPrefix("![") } == false)
    }

    @Test func theDependencyCountsWhatItAnswersOnEachComponent() {
        let counted = ProtectionDependenciesReport.build([
            ProtectionDependency(
                protectorId: "okta",
                protectorName: "Okta",
                protects: [
                    "credential-theft on store",
                    "unauthorized-access on store",
                    "account-takeover on github"
                ],
                unanswered: []
            )
        ])

        #expect(counted.first?.protectorId == "okta")
        #expect(counted.first?.answeredByElementId == ["store": 2, "github": 1])
    }

    @Test func theDependencySectionNamesEveryElementAControlProtects() throws {
        let lines = MarkdownProtectionDependencies.lines([
            ReportProtectionDependency(
                protectorName: "Okta",
                protectorId: "okta",
                protectsElements: [
                    ReportProtectedElement(
                        elementId: "store",
                        elementName: "Credential Store",
                        zoneName: "Corporate Cloud",
                        threats: [
                            ReportAnsweredThreat(
                                threatId: "credential-theft",
                                name: "Credential Theft",
                                riskScore: 5,
                                riskLevel: "medium"
                            ),
                            ReportAnsweredThreat(
                                threatId: "unauthorized-access",
                                name: "Unauthorized Access",
                                riskScore: 3,
                                riskLevel: "low"
                            )
                        ]
                    )
                ]
            )
        ])

        #expect(
            lines.contains(
                "Answers 2 threats on 1 element."
                    + " Every risk below is what is left after this control."
            )
        )
        #expect(lines.contains("| Element | Zone | Threats answered, with the risk left |"))
        #expect(
            lines.contains(
                "| Credential Store | Corporate Cloud"
                    + " | Credential Theft (medium 5), Unauthorized Access (low 3) |"
            )
        )
        #expect(lines.contains { $0.hasPrefix("- Answers:") } == false)
    }

    @Test func theDependencySectionFallsBackToTheRawLinesWithNoNames() {
        let lines = MarkdownProtectionDependencies.lines([
            ReportProtectionDependency(
                protectorName: "Okta",
                protects: ["credential-theft on store"]
            )
        ])

        #expect(lines.contains("- Answers: credential-theft on store"))
    }

    @Test func theDependencyStatesTheSameTotalAsThePictureDraws() {
        let built = ProtectionDependenciesReport.build(
            [
                ProtectionDependency(
                    protectorId: "okta",
                    protectorName: "Okta",
                    protects: [
                        "credential-theft on store",
                        "unauthorized-access on store",
                        // Never raised on the target, so neither the table nor
                        // the picture counts it.
                        "tampering on store"
                    ],
                    unanswered: []
                )
            ],
            threats: [
                threat(id: "credential-theft", sourceId: "component:store"),
                threat(id: "unauthorized-access", sourceId: "component:store")
            ],
            zones: [],
            nameOfComponent: { $0 }
        )

        #expect(built.first?.answeredByElementId == ["store": 2])
        #expect(built.first?.protectsElements.first?.threats.count == 2)
    }

    private func threat(id: String, sourceId: String) -> ReportThreat {
        ReportThreat(
            threatId: id,
            name: id,
            description: "",
            severityLabel: "medium",
            riskScore: 5,
            riskLevel: "medium",
            strideLabels: [],
            mitreTechniqueIds: [],
            sourceName: "store",
            sourceKind: "Component",
            sourceId: sourceId,
            controls: [],
            pathwayMitigationLabels: []
        )
    }

    /// The order rule of
    /// `docs/superpowers/specs/2026-09-17-trees-in-the-threat-list-design.md`:
    /// a recommendation on a threat that is an open step of an open tree
    /// sorts above a higher scoring recommendation that closes no route.
    @Test func aRouteClosingRecommendationSortsAboveAWorseOneThatClosesNoRoute() {
        let onARoute = ThreatKey(threatId: "a", sourceId: "component:one")
        let built = RecommendationsReport.build(
            threats: [threat("a", "one", 4), threat("b", "two", 12)],
            recommendations: [
                onARoute: [Recommendation(text: "close the route")],
                ThreatKey(threatId: "b", sourceId: "component:two"):
                    [Recommendation(text: "close nothing")]
            ],
            routeClosingThreats: [onARoute]
        )

        #expect(built.map(\.text) == ["close the route", "close nothing"])
    }

    /// Two recommendations on the same side of the rule keep the order the
    /// score and the text already gave them.
    @Test func twoRecommendationsOnNoRouteKeepTheOrderTheyHad() {
        let built = RecommendationsReport.build(
            threats: [threat("a", "one", 4), threat("b", "two", 12)],
            recommendations: [
                ThreatKey(threatId: "a", sourceId: "component:one"): [Recommendation(text: "first")],
                ThreatKey(threatId: "b", sourceId: "component:two"): [Recommendation(text: "second")]
            ],
            routeClosingThreats: []
        )

        #expect(built.map(\.text) == ["second", "first"])
    }
}
