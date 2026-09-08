import Testing
import ThreatModelKit

struct UpstreamGraphTests {
    private func link(_ id: String, _ source: String, _ target: String) -> Connection {
        Connection(id: ConnectionId(id), source: ComponentId(source), target: ComponentId(target))
    }

    private func graph(_ connections: [Connection]) -> UpstreamGraph {
        UpstreamGraph(connections: connections)
    }

    @Test func findsNothingUpstreamOfALoneComponent() {
        #expect(graph([]).upstream(of: ComponentId("c1")).isEmpty)
    }

    @Test func findsTheComponentOneHopUpstream() {
        let found = graph([link("k1", "a", "b")]).upstream(of: ComponentId("b"))

        #expect(found == [ComponentId("a")])
    }

    @Test func walksEveryHopBack() {
        // a -> b -> c -> d
        let found = graph([
            link("k1", "a", "b"),
            link("k2", "b", "c"),
            link("k3", "c", "d")
        ]).upstream(of: ComponentId("d"))

        #expect(found == [ComponentId("a"), ComponentId("b"), ComponentId("c")])
    }

    @Test func findsEveryBranchThatFeedsIn() {
        let found = graph([link("k1", "a", "c"), link("k2", "b", "c")])
            .upstream(of: ComponentId("c"))

        #expect(found == [ComponentId("a"), ComponentId("b")])
    }

    @Test func neverCountsAComponentAsUpstreamOfItself() {
        // A cycle: a -> b -> a. Spec section 5.3 makes upstream strict.
        let found = graph([link("k1", "a", "b"), link("k2", "b", "a")])
            .upstream(of: ComponentId("a"))

        #expect(found == [ComponentId("b")])
    }

    @Test func stopsRatherThanLoopingOnACycle() {
        // a -> b -> c -> b. The walk must finish.
        let found = graph([
            link("k1", "a", "b"),
            link("k2", "b", "c"),
            link("k3", "c", "b")
        ]).upstream(of: ComponentId("c"))

        #expect(found == [ComponentId("a"), ComponentId("b")])
    }

    @Test func ignoresWhatIsOnlyDownstream() {
        let found = graph([link("k1", "a", "b"), link("k2", "b", "c")])
            .upstream(of: ComponentId("a"))

        #expect(found.isEmpty)
    }

    @Test func findsOnlyTheComponentsOneHopDownstream() {
        // a -> b -> c. Directly downstream of a is b, not c.
        let found = graph([link("k1", "a", "b"), link("k2", "b", "c")])
            .directlyDownstream(of: ComponentId("a"))

        #expect(found == [ComponentId("b")])
    }

    @Test func findsEveryBranchOneHopDownstream() {
        let found = graph([link("k1", "a", "b"), link("k2", "a", "c")])
            .directlyDownstream(of: ComponentId("a"))

        #expect(found == [ComponentId("b"), ComponentId("c")])
    }
}
