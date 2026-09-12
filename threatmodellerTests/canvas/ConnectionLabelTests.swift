import Testing
import ThreatModelKit
@testable import threatmodeller

/// What a flow writes on the line.
struct ConnectionLabelTests {
    private func label(description: String?, kindId: String = "network") -> String {
        ConnectionsLayer(
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
        let written = ConnectionsLayer.cut(
            "opfilter System Extension (Endpoint Security)",
            to: ConnectionsLayer.guardLimit
        )

        #expect(written.count <= ConnectionsLayer.guardLimit)
        #expect(written.hasSuffix("\u{2026}"))
        #expect(written.hasPrefix("opfilter System"))
    }

    @Test func leavesAShortGuardNameWhole() {
        #expect(ConnectionsLayer.cut("WAF", to: ConnectionsLayer.guardLimit) == "WAF")
    }
}
