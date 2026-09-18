import CoreGraphics
import Testing
import ThreatModelKit
@testable import threatmodeller

/// What a flow writes on the line.
struct ConnectionLabelTests {
    private func label(description: String?, kindId: String = "network") -> String {
        ConnectionsLayer(
            origin: .zero,
            connections: [],
            boxes: [:],
            componentsById: [:],
            zones: [],
            risks: [:],
            guards: [:],
            outOfScopeComponentIds: [],
            selectedConnectionIds: [],
            preview: nil
        ).labelForTesting(
            ViewedConnection(
                id: "f1",
                sourceComponentId: "a",
                targetComponentId: "b",
                kindId: kindId,
                description: description
            )
        )
    }

    @Test func writesTheFlowKindWhenTheUserWroteNoDescription() {
        #expect(label(description: nil) == "Network")
        #expect(label(description: "   ") == "Network")
        #expect(label(description: nil, kindId: "syscall") == "System Call")
    }

    @Test func writesAShortDescriptionWhole() {
        #expect(label(description: "HTTPS") == "HTTPS")
    }

    @Test func keepsALongDescriptionWhole() {
        let described = "MCP over unix domain socket, newline-delimited JSON, signature-validated"

        // The callout is sized to the text, so nothing is cut.
        #expect(label(description: described) == described)
    }

    @Test func cutsAGuardsNameToWhatFitsOnAChip() {
        let written = FlowGeometry.cut(
            "opfilter System Extension (Endpoint Security)",
            to: FlowGeometry.guardLimit
        )

        #expect(written.count <= FlowGeometry.guardLimit)
        #expect(written.hasSuffix("\u{2026}"))
        #expect(written.hasPrefix("opfilter System"))
    }

    @Test func leavesAShortGuardNameWhole() {
        #expect(FlowGeometry.cut("WAF", to: FlowGeometry.guardLimit) == "WAF")
    }

    private func chipRun(guards: [EdgeGuard], openCount: Int = 0) -> BoundaryCrossings.BoundaryRun {
        BoundaryCrossings.BoundaryRun(
            zoneId: "z1",
            networkZoneId: "private",
            guards: guards,
            openCount: openCount,
            connectionIds: ["f1"],
            start: Point(x: 0, y: 0),
            end: Point(x: 0, y: 100),
            control: Point(x: 0, y: 50)
        )
    }

    private func edgeGuard(_ label: String) -> EdgeGuard {
        EdgeGuard(label: label, isAssumed: false)
    }

    @Test func writesEveryGuardsNameWhileThereAreGuardsShownOrFewer() {
        let run = chipRun(guards: [edgeGuard("WAF"), edgeGuard("mTLS")])

        #expect(FlowGeometry.chipTexts(of: run) == ["WAF", "mTLS"])
    }

    @Test func countsTheGuardsPastGuardsShownAsPlusN() {
        let names = (1 ... FlowGeometry.guardsShown + 2).map { "Guard \($0)" }
        let run = chipRun(guards: names.map(edgeGuard))

        let texts = FlowGeometry.chipTexts(of: run)

        #expect(texts == Array(names.prefix(FlowGeometry.guardsShown)) + ["+2"])
    }

    @Test func writesNoGuardWhenUnguardedWithAnOpenThreat() {
        let run = chipRun(guards: [], openCount: 1)

        #expect(FlowGeometry.chipTexts(of: run) == ["no guard"])
    }

    @Test func writesAnEmptyListWhenUnguardedWithNoOpenThreat() {
        let run = chipRun(guards: [], openCount: 0)

        #expect(FlowGeometry.chipTexts(of: run) == [])
    }

    @Test func cutsAGuardsNameAtItsBracket() {
        let label = "opfilter System Extension (Endpoint Security)"
        let run = chipRun(guards: [edgeGuard(label)])

        #expect(FlowGeometry.chipTexts(of: run) == [FlowGeometry.name(of: label)])
        #expect(FlowGeometry.chipTexts(of: run) == ["opfilter System Extension"])
    }
}
