import Testing
import ThreatModelKit
@testable import threatmodeller

/// The text a callout and a boundary chip carry.
struct CalloutTextTests {
    @Test func breaksALongTextIntoLines() {
        let lines = ConnectionsLayer.wrapped(
            "MCP over unix domain socket, newline-delimited JSON-RPC",
            perLine: 30
        )

        #expect(lines.count > 1)
        for line in lines { #expect(line.count <= 30) }
        #expect(lines.joined(separator: " ") == "MCP over unix domain socket, newline-delimited JSON-RPC")
    }

    @Test func leavesAShortTextOnOneLine() {
        #expect(ConnectionsLayer.wrapped("HTTPS", perLine: 30) == ["HTTPS"])
    }

    @Test func keepsAWordLongerThanALineWhole() {
        let lines = ConnectionsLayer.wrapped("NSXPCConnectionValidatedBySignature", perLine: 10)

        #expect(lines == ["NSXPCConnectionValidatedBySignature"])
    }

    @Test func readsAGuardsNameWithoutWhatFollowsItInBrackets() {
        #expect(
            ConnectionsLayer.name(of: "opfilter System Extension (Endpoint Security)")
                == "opfilter System Extension"
        )
    }

    @Test func readsAGuardsNameWithoutWhatFollowsAComma() {
        #expect(ConnectionsLayer.name(of: "WAF, managed") == "WAF")
    }

    @Test func leavesAShortGuardNameWhole() {
        #expect(ConnectionsLayer.name(of: "WAF") == "WAF")
    }

    @Test func stillCutsANameThatIsAllOneLongPhrase() {
        let written = ConnectionsLayer.name(
            of: "An extraordinarily long single phrase with no break at all"
        )

        #expect(written.count <= ConnectionsLayer.guardLimit)
        #expect(written.hasSuffix("\u{2026}"))
    }
}
