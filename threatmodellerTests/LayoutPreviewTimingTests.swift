import Foundation
import Testing
import ThreatModelKit
@testable import threatmodeller

/// The preview must not slow the search down.
///
/// The window's sampler stores each report and returns; it never draws on the
/// search's thread and never waits for the window. This states the margin on
/// the sixty-component sample the design measured.
/// `docs/superpowers/specs/2026-09-17-layout-preview-design.md`.
@Suite("The layout search with a preview attached")
struct LayoutPreviewTimingTests {
    /// How much longer the search may take with a listener attached. The
    /// measurement is under one per cent; a quarter leaves room for a slower
    /// machine and for the other tests the suite runs beside this one.
    private static let margin = 1.25

    /// Six zones of ten components, a chain of flows inside each zone, and
    /// one flow between neighbouring zones.
    private func sixtyComponents() -> ArchitectureSource {
        var zones: [SourceZone] = []
        var flows: [SourceFlow] = []
        for zoneIndex in 0 ..< 6 {
            var components: [SourceComponent] = []
            for step in 0 ..< 10 {
                let id = "z\(zoneIndex)c\(step)"
                components.append(SourceComponent(id: id, technologyId: "aws-ec2"))
                if step > 0 {
                    flows.append(
                        SourceFlow(
                            sourceId: "z\(zoneIndex)c\(step - 1)",
                            targetId: id,
                            kind: "network"
                        )
                    )
                }
            }
            zones.append(
                SourceZone(id: "z\(zoneIndex)", kind: "private", network: "vpc", components: components)
            )
            if zoneIndex > 0 {
                flows.append(
                    SourceFlow(
                        sourceId: "z\(zoneIndex - 1)c9",
                        targetId: "z\(zoneIndex)c0",
                        kind: "network"
                    )
                )
            }
        }
        return ArchitectureSource(systemName: "P", zones: zones, flows: flows)
    }

    @Test func finishesWithinTheMarginOfASearchNobodyWatches() {
        let request = LayOutModelRequest(source: sixtyComponents())

        let alone = Date()
        _ = LayOutModel().execute(request)
        let withoutAListener = Date().timeIntervalSince(alone)

        let progress = LayoutProgress()
        let sampler = LayoutPreviewSampler(redraw: {})
        progress.listen { report in sampler.receive(report) }
        let watched = Date()
        _ = LayOutModel(progress: progress).execute(request)
        let withAListener = Date().timeIntervalSince(watched)

        #expect(withAListener < withoutAListener * Self.margin)
    }
}
