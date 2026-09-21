import Testing
import ThreatModelKit

struct ActionsTests {
    private func edge(
        _ source: String,
        _ target: String,
        _ action: EdgeAction? = nil
    ) -> MitigatesEdge {
        MitigatesEdge(
            source: ComponentId(source),
            target: ComponentId(target),
            status: .proposed,
            action: action
        )
    }

    @Test func buildsOneActionFromOneEdge() {
        let actions = Actions.build(
            from: [edge("guard", "store", EdgeAction(label: "adopt", text: "Adopt the guard"))]
        )

        #expect(actions.count == 1)
        #expect(actions[0].label == "adopt")
        #expect(actions[0].text == "Adopt the guard")
        #expect(actions[0].edgeIds == ["guard->store"])
    }

    @Test func buildsOneActionFromEveryEdgeSharingItsLabel() {
        let actions = Actions.build(
            from: [
                edge("guard", "store", EdgeAction(label: "adopt", text: "Adopt the guard")),
                edge("guard", "queue", EdgeAction(label: "adopt")),
                edge("other", "store", EdgeAction(label: "something-else", text: "Do the other thing"))
            ]
        )

        #expect(actions.count == 2)
        #expect(actions[0].edgeIds == ["guard->store", "guard->queue"])
        #expect(actions[1].edgeIds == ["other->store"])
    }

    @Test func keepsTheNoteTheBlockerAndTheSourcesFromTheEdgeStatingTheText() {
        let actions = Actions.build(
            from: [
                edge("guard", "queue", EdgeAction(label: "adopt")),
                edge(
                    "guard",
                    "store",
                    EdgeAction(
                        label: "adopt",
                        text: "Adopt the guard",
                        note: "It is bought and not deployed.",
                        blockedBy: "guard-not-deployed",
                        sources: ["https://example.com/ticket/1"]
                    )
                )
            ]
        )

        #expect(actions[0].note == "It is bought and not deployed.")
        #expect(actions[0].blockedBy == "guard-not-deployed")
        #expect(actions[0].sources == ["https://example.com/ticket/1"])
        // Both edges belong to it, in the order the file declares them.
        #expect(actions[0].edgeIds == ["guard->queue", "guard->store"])
    }

    @Test func ordersActionsByWhereTheirTextIsDeclared() {
        // The edge mentioning "first" comes before the edge stating "second"'s
        // text, so ordering by first mention and ordering by text declaration
        // disagree. "second" states its text first, so it comes first.
        let actions = Actions.build(
            from: [
                edge("x", "one", EdgeAction(label: "first")),
                edge("b", "two", EdgeAction(label: "second", text: "Second")),
                edge("a", "three", EdgeAction(label: "first", text: "First"))
            ]
        )

        #expect(actions.map(\.label) == ["second", "first"])
    }

    @Test func buildsNothingFromEdgesThatNameNoAction() {
        #expect(Actions.build(from: [edge("guard", "store")]).isEmpty)
    }

    @Test func buildsNothingForALabelNoEdgeGivesTextTo() {
        // The parser reports this and drops the blocks. Build refuses it too,
        // so a model reaching here by another route cannot make a nameless
        // action.
        #expect(Actions.build(from: [edge("guard", "store", EdgeAction(label: "adopt"))]).isEmpty)
    }
}
