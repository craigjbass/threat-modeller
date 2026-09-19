import Foundation
import Testing
import ThreatModelKit

/// What the layout search tells a listener while it runs, on a sample large
/// enough to hold real wins and real losses.
/// `docs/superpowers/specs/2026-09-17-layout-preview-design.md` states the
/// decision.
@Suite("The layout search reporting while it runs")
struct LayoutReportTests {
    /// Six zones of ten components, a chain of flows inside each zone, and one
    /// flow between neighbouring zones.
    private func sixtyComponents() -> ArchitectureSource {
        sample(zones: 6, perZone: 10)
    }

    private func sample(zones zoneCount: Int, perZone: Int) -> ArchitectureSource {
        var zones: [SourceZone] = []
        var flows: [SourceFlow] = []
        for zoneIndex in 0 ..< zoneCount {
            var components: [SourceComponent] = []
            for step in 0 ..< perZone {
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
                SourceZone(
                    id: "z\(zoneIndex)",
                    kind: "private",
                    network: "vpc",
                    components: components
                )
            )
            if zoneIndex > 0 {
                flows.append(
                    SourceFlow(
                        sourceId: "z\(zoneIndex - 1)c\(perZone - 1)",
                        targetId: "z\(zoneIndex)c0",
                        kind: "network"
                    )
                )
            }
        }
        return ArchitectureSource(systemName: "P", zones: zones, flows: flows)
    }

    private func run(_ source: ArchitectureSource) -> HeardReports {
        let heard = HeardReports()
        let progress = LayoutProgress()
        progress.listen { report in heard.add(report.fitness.score) }
        _ = LayOutModel(progress: progress).execute(LayOutModelRequest(source: source))
        return heard
    }

    @Test func reportsFarMoreThanItsImprovedPlans() {
        let heard = run(sixtyComponents())

        #expect(heard.count() > heard.improvements() + 1)
    }

    @Test func reportsAWorsePlanThanTheOneBefore() {
        let heard = run(sixtyComponents())

        #expect(heard.worsenings() > 0)
    }
}

/// The scores a listener heard, in the order the search reported them.
private final class HeardReports: @unchecked Sendable {
    private let lock = NSLock()
    private var scores: [Double] = []

    func add(_ score: Double) {
        lock.lock()
        scores.append(score)
        lock.unlock()
    }

    func count() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return scores.count
    }

    /// How many reports carry a better plan than the report before.
    func improvements() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return zip(scores, scores.dropFirst()).count { $0.0 > $0.1 }
    }

    /// How many reports carry a worse plan than the report before.
    func worsenings() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return zip(scores, scores.dropFirst()).count { $0.0 < $0.1 }
    }
}
