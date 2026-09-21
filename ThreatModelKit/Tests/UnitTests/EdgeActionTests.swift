import Testing
import ThreatModelKit

struct EdgeActionTests {
    @Test func anEdgeCarriesNoActionUnlessOneIsGiven() {
        let edge = MitigatesEdge(
            source: ComponentId("guard"),
            target: ComponentId("store"),
        )

        #expect(edge.action == nil)
    }

    @Test func anEdgeCarriesTheActionThatWouldAdoptIt() {
        let edge = MitigatesEdge(
            source: ComponentId("guard"),
            target: ComponentId("store"),
            status: .proposed,
            action: EdgeAction(
                label: "adopt-the-guard",
                text: "Adopt the guard",
                note: "It is bought and not deployed.",
                blockedBy: "guard-not-deployed",
                sources: ["https://example.com/ticket/1"]
            )
        )

        #expect(edge.action?.label == "adopt-the-guard")
        #expect(edge.action?.text == "Adopt the guard")
        #expect(edge.action?.blockedBy == "guard-not-deployed")
    }

    @Test func anEdgeThatOnlyJoinsAnActionStatesNoText() {
        let action = EdgeAction(label: "adopt-the-guard")

        #expect(action.text == nil)
        #expect(action.note == nil)
        #expect(action.sources.isEmpty)
    }
}
