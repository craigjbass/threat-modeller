import Testing
import ThreatModelKit

struct ReportRollupTests {
    private func threat(
        _ name: String,
        source: String,
        sourceId: String? = nil,
        kind: String = "Component",
        score: Int,
        level: String = "high"
    ) -> ReportThreat {
        ReportThreat(
            threatId: name,
            name: name,
            description: "",
            severityLabel: "High",
            riskScore: score,
            riskLevel: level,
            strideLabels: [],
            mitreTechniqueIds: [],
            sourceName: source,
            sourceKind: kind,
            sourceId: sourceId ?? "component:\(source)",
            controls: [],
            pathwayMitigationLabels: []
        )
    }

    private func zone(_ name: String, _ holds: [String], ids: [String]? = nil) -> ReportZone {
        ReportZone(
            name: name,
            networkZoneLabel: "Private Zone",
            networkTypeLabel: "Generic Network",
            componentNames: holds,
            componentIds: ids ?? holds,
            riskReductionPercent: 20
        )
    }

    @Test func aZoneRollupCountsWhatItHolds() throws {
        let tables = ReportRollups.build(
            threats: [
                threat("a", source: "api", score: 12, level: "critical"),
                threat("b", source: "api", score: 4, level: "medium"),
                threat("c", source: "outside", score: 8)
            ],
            zones: [zone("App VPC", ["api"])]
        )
        let rollup = try #require(tables.byZone.first)
        #expect(rollup.zoneName == "App VPC")
        #expect(rollup.componentCount == 1)
        #expect(rollup.worstScore == 12)
        #expect(rollup.byLevel.contains { $0.label == "critical" && $0.count == 1 })
    }

    @Test func aZoneRollupMatchesByIdNotByDisplayName() throws {
        let tables = ReportRollups.build(
            threats: [
                threat("t", source: "PostgreSQL", sourceId: "component:db-1", score: 9, level: "high")
            ],
            zones: [
                zone("Zone A", ["PostgreSQL"], ids: ["db-1"]),
                zone("Zone B", ["PostgreSQL"], ids: ["db-2"])
            ]
        )
        let zoneA = try #require(tables.byZone.first { $0.zoneName == "Zone A" })
        let zoneB = try #require(tables.byZone.first { $0.zoneName == "Zone B" })
        #expect(zoneA.worstScore == 9)
        #expect(zoneB.worstScore == 0)
    }

    @Test func theTopResidualTableHoldsTheWorstTwentyWorstFirst() {
        let threats = (1...25).map { threat("t\($0)", source: "api", score: $0) }
        let tables = ReportRollups.build(threats: threats, zones: [])
        #expect(tables.topResidual.count == 20)
        #expect(tables.topResidual.first?.riskScore == 25)
        #expect(tables.topResidual.last?.riskScore == 6)
    }

    @Test func theCountsBySourceKindNameTheThree() {
        let tables = ReportRollups.build(
            threats: [
                threat("a", source: "api", kind: "Component", score: 4),
                threat("b", source: "api->db", kind: "Connection", score: 4),
                threat("c", source: "vpc", kind: "Zone", score: 4),
                threat("d", source: "api", kind: "Component", score: 4)
            ],
            zones: []
        )
        #expect(tables.bySourceKind == [
            ReportCount(label: "Component", count: 2),
            ReportCount(label: "Connection", count: 1),
            ReportCount(label: "Zone", count: 1)
        ])
    }

    @Test func theMarkdownWritesNothingForAnEmptyModel() {
        #expect(MarkdownRollups.lines(ReportRollupTables.empty, showsAssumed: false).isEmpty)
    }

    @Test func theMarkdownDrawsTheTopResidualTable() {
        let lines = MarkdownRollups.lines(
            ReportRollupTables(
                byZone: [],
                topResidual: [threat("Raw device read", source: "store", score: 12, level: "critical")],
                bySourceKind: []
            ),
            showsAssumed: false
        )
        #expect(lines.contains("## Top residual risk"))
        #expect(lines.contains("| Raw device read | store | 12 | 12 | critical |"))
    }

    /// I3: the column reads off the model's own assumed edges, not off
    /// whether a row in this table happens to differ under them. A threat
    /// can drop out of the top-20 prefix while an assumed edge still stands
    /// elsewhere, and the column must still show.
    @Test func theTopResidualColumnShowsWhenTheModelHasAnAssumedEdgeEvenIfNoRowDiffers() {
        let lines = MarkdownRollups.lines(
            ReportRollupTables(
                byZone: [],
                topResidual: [threat("Raw device read", source: "store", score: 12, level: "critical")],
                bySourceKind: []
            ),
            showsAssumed: true
        )
        #expect(lines.contains("| Threat | Raised by | Residual | If assumed hold | Before controls | Level |"))
        #expect(lines.contains("| Raw device read | store | 12 | 12 | 12 | critical |"))
    }

    @Test func theTopResidualColumnHidesWhenTheModelHasNoAssumedEdge() {
        let lines = MarkdownRollups.lines(
            ReportRollupTables(
                byZone: [],
                topResidual: [threat("Raw device read", source: "store", score: 12, level: "critical")],
                bySourceKind: []
            ),
            showsAssumed: false
        )
        #expect(lines.contains("| Threat | Raised by | Residual | Before controls | Level |"))
        #expect(lines.contains { $0.contains("If assumed hold") } == false)
    }

    @Test func theByZoneTableGainsTheColumnWhenTheModelHasAnAssumedEdge() throws {
        let tables = ReportRollups.build(
            threats: [
                ReportThreat(
                    threatId: "a",
                    name: "a",
                    description: "",
                    severityLabel: "High",
                    riskScore: 12,
                    riskLevel: "critical",
                    strideLabels: [],
                    mitreTechniqueIds: [],
                    sourceName: "api",
                    sourceKind: "Component",
                    sourceId: "component:api",
                    controls: [],
                    pathwayMitigationLabels: [],
                    scoreIfAssumptionsHold: 3
                )
            ],
            zones: [zone("App VPC", ["api"])]
        )
        let rollup = try #require(tables.byZone.first)
        #expect(rollup.worstScore == 12)
        #expect(rollup.worstScoreIfAssumptionsHold == 3)

        let lines = MarkdownRollups.lines(tables, showsAssumed: true)
        #expect(lines.contains("| Zone | Components | Worst | If assumed hold | Levels |"))
        #expect(lines.contains { $0.contains("App VPC") && $0.contains("| 12 | 3 |") })
    }
}
