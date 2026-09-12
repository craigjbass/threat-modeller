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

    @Test func cutsALongDescriptionToWhatFitsOnTheLine() {
        let written = label(
            description: "MCP over unix domain socket, newline-delimited JSON, signature-validated"
        )

        #expect(written.count <= ConnectionsLayer.labelLimit)
        #expect(written.hasSuffix("\u{2026}"))
        #expect(written.hasPrefix("MCP over unix"))
    }
}
