import Testing
import ThreatModelKit
import TestSupport

/// The order rule of
/// `docs/superpowers/specs/2026-09-17-trees-in-the-threat-list-design.md`:
/// a control that closes a step on an open tree sorts before a control that
/// does not, and the rest keep the order they had.
@Suite("Route closing comes first")
struct RouteClosingTests {
    private func tree(
        id: String = "t",
        name: String = "Read every record",
        open: Bool = true,
        stale: Bool = false,
        steps: [(String, StepState)] = [("ssrf", .open)],
        sufficient: [String] = []
    ) -> BoundAttackTree {
        BoundAttackTree(
            id: id,
            name: name,
            description: nil,
            raisesRiskBy: 40,
            goal: ThreatKey(threatId: "exfiltration", sourceId: "component:db"),
            goalName: "Exfiltration",
            goalSourceName: "db",
            steps: steps.map {
                BoundStep(
                    key: ThreatKey(threatId: $0.0, sourceId: "component:api"),
                    threatName: $0.0,
                    sourceName: "api",
                    state: $0.1,
                    factor: 1
                )
            },
            chainFactor: open ? 1 : 0,
            isOpen: open,
            isStale: stale,
            scoreBefore: 5,
            score: open ? 7 : 5,
            sufficientControls: sufficient.map {
                BoundSufficientControl(description: $0, state: .open)
            }
        )
    }

    @Test func anOpenStepOfAnOpenTreeIsARoute() {
        let steps = RouteClosing.openSteps(on: [tree()])

        #expect(steps.keys.contains(ThreatKey(threatId: "ssrf", sourceId: "component:api")))
        #expect(steps[ThreatKey(threatId: "ssrf", sourceId: "component:api")]?.map(\.name)
            == ["Read every record"])
    }

    @Test func aClosedStepIsNoRoute() {
        #expect(RouteClosing.openSteps(on: [tree(steps: [("ssrf", .closed)])]).isEmpty)
    }

    @Test func aClosedTreeAndAStaleTreeAreNoRoute() {
        #expect(RouteClosing.openSteps(on: [tree(open: false)]).isEmpty)
        #expect(RouteClosing.openSteps(on: [tree(stale: true)]).isEmpty)
    }

    /// A tree names a control as sufficient, so that one control closes the
    /// whole route whatever threat answers it.
    @Test func aSufficientControlOfAnOpenTreeIsARoute() {
        let found = RouteClosing.sufficientControls(on: [tree(sufficient: ["Segment the network"])])

        #expect(found[ControlIdentity.fingerprint(of: "Segment  the network")]?.map(\.name)
            == ["Read every record"])
        #expect(RouteClosing.sufficientControls(on: [tree(open: false, sufficient: ["Segment the network"])])
            .isEmpty)
    }

    @Test func theRouteClosingItemsComeFirstAndTheRestHoldTheirOrder() {
        let ordered = RouteClosing.first(["a", "b", "c", "d"]) { $0 == "b" || $0 == "d" }

        #expect(ordered == ["b", "d", "a", "c"])
    }
}
