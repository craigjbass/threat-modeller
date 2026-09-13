import Testing
import ThreatModelKit

/// Five paths a reader can follow, not twenty that repeat their first two
/// steps.
struct AttackPathCurationTests {
    private func hop(_ name: String, _ score: Int = 0) -> ReportAttackPathHop {
        ReportAttackPathHop(
            componentName: name,
            flowKindLabel: nil,
            worstThreatName: nil,
            riskScore: score,
            reducedBy: []
        )
    }

    private func path(_ names: [String], _ worst: Int) -> ReportAttackPath {
        ReportAttackPath(
            startName: names.first ?? "",
            endName: names.last ?? "",
            hops: names.map { hop($0) },
            worstScore: worst
        )
    }

    @Test func statesTheSharedPrefixOnceAndTrimsItFromEveryPath() {
        let curated = AttackPaths.curate([
            path(["Internet", "GUI", "Store"], 13),
            path(["Internet", "GUI", "Queue"], 9)
        ], beyond: 0)

        #expect(curated.prefix.map(\.componentName) == ["Internet", "GUI"])
        #expect(curated.paths[0].hops.map(\.componentName) == ["Store"])
        #expect(curated.paths[1].hops.map(\.componentName) == ["Queue"])
    }

    @Test func statesNoPrefixWhenThePathsShareNoFirstHop() {
        let curated = AttackPaths.curate([
            path(["Internet", "Store"], 13),
            path(["Laptop", "Store"], 9)
        ], beyond: 0)

        #expect(curated.prefix.isEmpty)
        #expect(curated.paths[0].hops.count == 2)
    }

    @Test func keepsAPathTheTrimWouldEmpty() {
        let curated = AttackPaths.curate([
            path(["Internet", "GUI"], 13),
            path(["Internet", "GUI", "Store"], 9)
        ], beyond: 0)

        // Trimming the whole of the first path leaves no story, so the
        // prefix stops one hop short of the shortest path.
        #expect(curated.prefix.map(\.componentName) == ["Internet"])
        #expect(curated.paths[0].hops.map(\.componentName) == ["GUI"])
        #expect(curated.paths[1].hops.map(\.componentName) == ["GUI", "Store"])
    }

    @Test func listsFiveAndSummarisesTheRest() {
        let many = (1...8).map { path(["Internet", "Target\($0)"], 16 - $0) }

        let curated = AttackPaths.curate(many, beyond: 0)

        #expect(curated.paths.count == 5)
        #expect(curated.notListed.count == 3)
        #expect(curated.notListed.first?.endName == "Target6")
        #expect(curated.notListed.first?.worstScore == 10)
        #expect(curated.beyond == 0)
    }

    @Test func carriesTheCountOfWhatTheTraceFoundBeyondTheAppendix() {
        let curated = AttackPaths.curate([path(["Internet", "Store"], 13)], beyond: 7)

        #expect(curated.beyond == 7)
    }

    @Test func writesNoPrefixForASinglePath() {
        let curated = AttackPaths.curate([path(["Internet", "GUI", "Store"], 13)], beyond: 0)

        #expect(curated.prefix.isEmpty)
        #expect(curated.paths[0].hops.count == 3)
    }
}
