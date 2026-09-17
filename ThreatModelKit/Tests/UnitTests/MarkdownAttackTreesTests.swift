import Testing
import ThreatModelKit

@Suite("The attack tree section of the report")
struct MarkdownAttackTreesTests {
    private func step(
        _ name: String,
        _ state: StepState,
        closedBy: String? = nil,
        chain: Int? = nil,
        position: Int? = nil
    ) -> BoundStep {
        BoundStep(
            key: ThreatKey(threatId: name, sourceId: "component:api"),
            threatName: name,
            sourceName: "Application Server",
            state: state,
            closedBy: closedBy,
            factor: 1.0,
            note: nil,
            chain: chain,
            position: position
        )
    }

    private func tree(
        steps: [BoundStep] = [],
        isOpen: Bool = true,
        isStale: Bool = false,
        sufficientControls: [BoundSufficientControl] = [],
        closedBy: String? = nil
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
            score: 7,
            sufficientControls: sufficientControls,
            closedBy: closedBy
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

    /// A chain prints as an ordered route, one line per link with its
    /// position, not as a bag.
    @Test func printsTheLinksOfAChainNumberedInOrder() {
        let lines = MarkdownAttackTrees.lines(
            [tree(steps: [
                step("Server-Side Request Forgery", .open, chain: 1, position: 1),
                step("Credential Theft", .closed, closedBy: "Enforce IMDSv2", chain: 1, position: 2),
                step("Privilege Escalation", .open, chain: 1, position: 3),
            ])],
            routes: 1
        )

        let text = lines.joined(separator: "\n")
        #expect(text.contains("""
        The chain, in order:

        1. Server-Side Request Forgery on Application Server, open
        2. Credential Theft on Application Server, closed by Enforce IMDSv2
        3. Privilege Escalation on Application Server, open
        """))
    }

    @Test func numbersEachChainOfATreeThatHoldsTwo() {
        let lines = MarkdownAttackTrees.lines(
            [tree(steps: [
                step("A", .open, chain: 1, position: 1),
                step("B", .open, chain: 1, position: 2),
                step("C", .open, chain: 2, position: 1),
                step("D", .open, chain: 2, position: 2),
            ])],
            routes: 1
        )

        #expect(lines.contains("Chain 1, in order:"))
        #expect(lines.contains("Chain 2, in order:"))
        #expect(lines.contains("2. D on Application Server, open"))
    }

    /// Two steps of a branch that is the first link share position 1 and
    /// print on one line.
    @Test func printsABranchLinkOnOneLine() {
        let lines = MarkdownAttackTrees.lines(
            [tree(steps: [
                step("A", .open, chain: 1, position: 1),
                step("B", .open, chain: 1, position: 1),
                step("C", .open, chain: 1, position: 2),
            ])],
            routes: 1
        )

        #expect(lines.contains("1. A on Application Server, open; B on Application Server, open"))
        #expect(lines.contains("2. C on Application Server, open"))
    }

    @Test func printsNoChainForATreeOfBranchesAlone() {
        let lines = MarkdownAttackTrees.lines([tree(steps: [step("A", .open)])], routes: 1)

        #expect(lines.contains { $0.contains("in order:") } == false)
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
    // MARK: the controls that are sufficient to close the whole route

    @Test func namesTheSufficientControlThatClosedTheTreeInTheHeading() {
        let lines = MarkdownAttackTrees.lines(
            [tree(
                steps: [step("Credential Theft", .open)],
                isOpen: false,
                sufficientControls: [
                    BoundSufficientControl(description: "Segment the network", state: .closes)
                ],
                closedBy: "Segment the network"
            )],
            routes: 1
        )

        #expect(lines.contains("### Read every customer record \u{2014} closed by Segment the network"))
    }

    @Test func listsEachSufficientControlWithItsState() {
        let lines = MarkdownAttackTrees.lines(
            [tree(sufficientControls: [
                BoundSufficientControl(description: "Segment the network", state: .closes),
                BoundSufficientControl(description: "Alert on the route", state: .open),
                BoundSufficientControl(description: "Rotate the keys", state: .unevidenced),
                BoundSufficientControl(description: "Segmnet the network", state: .unknown),
            ], closedBy: "Segment the network")],
            routes: 1
        )

        let text = lines.joined(separator: "\n")
        #expect(text.contains("""
        Sufficient controls:

        - Segment the network: closes the tree
        - Alert on the route: not implemented
        - Rotate the keys: implemented with no evidence
        - Segmnet the network: not a control the catalogue or the libraries hold
        """))
    }

    @Test func listsNoSufficientControlsForATreeThatNamesNone() {
        let lines = MarkdownAttackTrees.lines([tree()], routes: 1)

        #expect(lines.contains("Sufficient controls:") == false)
    }
}
