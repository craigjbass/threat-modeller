import ArchitectureDSL
import Testing
import ThreatModelKit

/// Every stanza the governance writer can put down is a stanza the governance
/// parser reads back. Issue #144: a file the writer wrote stopped the window
/// from opening the project, so the writer and the parser are held together
/// here over every shape at once.
@Suite("Every governance stanza the writer writes parses back")
struct GovernanceWriterTests {
    private let source = HclGovernanceSource()

    /// An accepted stanza with every attribute, and one with none.
    private func accepted(_ control: String, full: Bool, isStale: Bool) -> SourceAcceptedRisk {
        guard full else { return SourceAcceptedRisk(control: control, isStale: isStale) }
        return SourceAcceptedRisk(
            control: control,
            owner: "Head of Platform",
            acceptedOn: "2026-01-05",
            reviewBy: "2026-07-05",
            rationale: "the credential is scoped to one read-only role",
            sources: ["https://example.com/risk-register/RSK-412"],
            isStale: isStale
        )
    }

    private func work(_ label: String, full: Bool, isStale: Bool) -> SourcePlannedWork {
        guard full else { return SourcePlannedWork(label: label, isStale: isStale) }
        return SourcePlannedWork(
            label: label,
            owner: "Platform team",
            effort: "medium",
            dueBy: "2026-11-30",
            status: "in_progress",
            acceptance: "The plist is writable only by the MDM daemon.",
            note: "The rollout waits on the SSO migration.",
            sources: ["https://example.com/ticket/1"],
            isStale: isStale
        )
    }

    /// One governance file holding every combination of stale and not stale at
    /// every level, over every source kind a threat block can name.
    private func everyShape() -> GovernanceSource {
        var threats: [SourceGovernedThreat] = []
        var index = 0
        for kind in ["component", "zone", "flow"] {
            for threatIsStale in [false, true] {
                for acceptedIsStale in [false, true] {
                    for workIsStale in [false, true] {
                        for full in [false, true] {
                            index += 1
                            threats.append(
                                SourceGovernedThreat(
                                    threatId: "t\(index)",
                                    sourceKind: kind,
                                    sourceId: "s\(index)",
                                    accepted: [
                                        accepted("c\(index)", full: full, isStale: acceptedIsStale)
                                    ],
                                    work: [work("w\(index)", full: full, isStale: workIsStale)],
                                    isStale: threatIsStale
                                )
                            )
                        }
                    }
                }
            }
        }

        var actions: [SourcePlannedWork] = []
        for actionIsStale in [false, true] {
            for full in [false, true] {
                index += 1
                actions.append(work("a\(index)", full: full, isStale: actionIsStale))
            }
        }

        return GovernanceSource(systemName: "Payments", threats: threats, actions: actions)
    }

    @Test func everyStanzaShapeReadsBackAsItWasWritten() throws {
        let written = source.write(everyShape())
        let read = source.read(written)

        #expect(read.diagnostics.map(\.message) == [], "the writer wrote:\n\(written)")
        #expect(try #require(read.source) == everyShape())
    }

    @Test func writingWhatWasReadWritesTheSameBytes() throws {
        let written = source.write(everyShape())
        let read = try #require(source.read(written).source)

        #expect(source.write(read) == written)
    }

    /// A threat with no accepted stanza and no work, and an accepted stanza
    /// with no attribute, are both shapes the compile writes.
    @Test func readsBackAThreatBlockThatStatesNothing() throws {
        let empty = GovernanceSource(
            systemName: "Payments",
            threats: [
                SourceGovernedThreat(threatId: "t", sourceKind: "component", sourceId: "api"),
                SourceGovernedThreat(
                    threatId: "t",
                    sourceKind: "zone",
                    sourceId: "edge",
                    accepted: [SourceAcceptedRisk(control: "c")],
                    isStale: true
                )
            ],
            actions: [SourcePlannedWork(label: "a")]
        )
        let written = source.write(empty)
        let read = source.read(written)

        #expect(read.diagnostics.map(\.message) == [], "the writer wrote:\n\(written)")
        #expect(try #require(read.source) == empty)
    }

    /// A quotation mark, a backslash, a newline and a tab in a label go
    /// through the writer and come back the same.
    @Test func readsBackALabelHoldingTheCharactersTheWriterEscapes() throws {
        let awkward = GovernanceSource(
            systemName: "Pay \"ments\"",
            threats: [
                SourceGovernedThreat(
                    threatId: "t\\1",
                    sourceKind: "flow",
                    sourceId: "api->db",
                    accepted: [
                        SourceAcceptedRisk(
                            control: "hold the \"key\"\nand the\ttab",
                            owner: "a\\b"
                        )
                    ]
                )
            ]
        )
        let written = source.write(awkward)
        let read = source.read(written)

        #expect(read.diagnostics.map(\.message) == [], "the writer wrote:\n\(written)")
        #expect(try #require(read.source) == awkward)
    }
}
