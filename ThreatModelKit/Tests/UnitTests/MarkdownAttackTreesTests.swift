import Testing
import ThreatModelKit

@Suite("The attack tree section of the report")
struct MarkdownAttackTreesTests {
    private func step(_ name: String, _ state: StepState, closedBy: String? = nil) -> BoundStep {
        BoundStep(
            key: ThreatKey(threatId: name, sourceId: "component:api"),
            threatName: name,
            sourceName: "Application Server",
            state: state,
            closedBy: closedBy,
            factor: 1.0,
            note: nil
        )
    }

    private func tree(
        steps: [BoundStep] = [],
        isOpen: Bool = true,
        isStale: Bool = false
    ) -> BoundAttackTree {
        BoundAttackTree(
            id: "read-every-customer-record",
            name: "Read every customer record",
            description: "An unauthenticated caller reaches the customer table.",
            raisesRiskBy: 40,
            goal: ThreatKey(threatId: "data-exfiltration", sourceId: "component:db"),
            goalName: "Data Exfiltration",
            goalSourceName: "PostgreSQL Database",
            steps: steps,
            chainFactor: 1.0,
            isOpen: isOpen,
            isStale: isStale,
            scoreBefore: 5,
            score: 7
        )
    }

    @Test func writesNoSectionWhenAModelStatesNoTree() {
        #expect(MarkdownAttackTrees.lines([], routes: 20).isEmpty)
    }

    @Test func writesTheHeadingWithBothScoresAndTheChain() {
        let lines = MarkdownAttackTrees.lines([tree()], routes: 20)

        #expect(lines.contains("## Attack trees"))
        #expect(lines.contains("### Read every customer record \u{2014} 5 \u{2192} 7, chain 100%"))
        #expect(lines.contains("Goal: Data Exfiltration on PostgreSQL Database."))
    }

    @Test func statesHowManyRoutesTheWalkFoundBesideTheTreesAPersonWrote() {
        let lines = MarkdownAttackTrees.lines([tree()], routes: 20)

        #expect(lines.contains("This model states 1 tree. The walk found 20 routes."))
    }

    @Test func namesTheControlThatClosedAStep() {
        let lines = MarkdownAttackTrees.lines(
            [tree(steps: [step("Credential Theft", .closed, closedBy: "Enforce IMDSv2")])],
            routes: 1
        )

        #expect(lines.contains("| Step | Raised on | State | Closed by |"))
        #expect(
            lines.contains("| Credential Theft | Application Server | closed | Enforce IMDSv2 |")
        )
    }

    @Test func writesADashForAStepNothingClosed() {
        let lines = MarkdownAttackTrees.lines(
            [tree(steps: [step("Credential Theft", .open)])],
            routes: 1
        )

        #expect(
            lines.contains("| Credential Theft | Application Server | open | \u{2014} |")
        )
    }

    @Test func saysATreeNoLongerBindsRatherThanNamingAScore() {
        let lines = MarkdownAttackTrees.lines([tree(isOpen: false, isStale: true)], routes: 1)

        #expect(lines.contains("### Read every customer record \u{2014} no longer binds"))
    }

    /// A closed tree sharing a goal with an open one reads the open one's
    /// raised score, because `score` is the goal's score after every tree.
    /// The heading states what the tree did rather than that number.
    @Test func saysEveryRouteIsClosedRatherThanNamingAScore() {
        let lines = MarkdownAttackTrees.lines([tree(isOpen: false)], routes: 1)

        #expect(lines.contains("### Read every customer record \u{2014} every route is closed"))
    }

    @Test func writesTheWorstTreeFirst() throws {
        let worse = BoundAttackTree(
            id: "worse",
            name: "Worse",
            description: nil,
            raisesRiskBy: 40,
            goal: ThreatKey(threatId: "t", sourceId: "component:db"),
            goalName: "T",
            goalSourceName: "Database",
            steps: [],
            chainFactor: 1.0,
            isOpen: true,
            isStale: false,
            scoreBefore: 10,
            score: 14
        )

        let text = MarkdownAttackTrees.lines([tree(), worse], routes: 2).joined(separator: "\n")

        let first = try #require(text.range(of: "### Worse"))
        let second = try #require(text.range(of: "### Read every customer record"))
        #expect(first.lowerBound < second.lowerBound)
    }
}
