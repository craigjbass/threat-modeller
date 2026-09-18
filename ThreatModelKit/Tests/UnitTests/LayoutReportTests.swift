import Foundation
import Testing
import ThreatModelKit

/// What the layout search tells a listener while it runs.
///
/// A large model spends most of its time scoring candidates that improve
/// nothing. So the search reports the best plan on two triggers: every
/// improvement, and every `LayoutProgress.reportInterval` of search time.
/// `docs/superpowers/specs/2026-09-17-layout-preview-design.md` states both
/// triggers and the measured frame counts.
@Suite("The layout search reporting while it runs")
struct LayoutReportTests {
    /// Six zones of ten components, a chain of flows inside each zone, and one
    /// flow between neighbouring zones.
    private func sixtyComponents() -> ArchitectureSource {
        sample(zones: 6, perZone: 10)
    }

    /// Small enough that the kit's debug build searches it in a moment.
    private func aSmallSample() -> ArchitectureSource {
        sample(zones: 3, perZone: 4)
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

    private func run(
        _ source: ArchitectureSource,
        steppingBy step: TimeInterval
    ) -> (clock: SteppingClock, heard: HeardReports) {
        let clock = SteppingClock(step: step)
        let heard = HeardReports()
        let progress = LayoutProgress()
        progress.listen { report in heard.add(report.fitness.score) }
        _ = LayOutModel(progress: progress, now: { clock.reading() })
            .execute(LayOutModelRequest(source: source))
        return (clock, heard)
    }

    /// The count the interval asks for over a search of this length. The
    /// search reads its clock once for each candidate, so a search whose
    /// candidates are further apart than the interval reports once for each
    /// candidate instead.
    private func reportsTheIntervalAsksFor(_ duration: TimeInterval) -> Int {
        Int(duration / LayoutProgress.reportInterval) - 1
    }

    @Test func reportsTheSixtyComponentSampleOnTheClockBetweenItsFiveImprovedPlans() {
        let (clock, heard) = run(sixtyComponents(), steppingBy: LayoutProgress.reportInterval / 4)

        #expect(heard.count() >= reportsTheIntervalAsksFor(clock.elapsed()))
        #expect(heard.improvements() == 4)
        #expect(heard.count() > heard.improvements() + 1)
    }

    @Test func twoReportsInARowNeverCarryAWorsePlan() {
        let (_, heard) = run(aSmallSample(), steppingBy: LayoutProgress.reportInterval / 4)

        #expect(heard.count() > 1)
        #expect(heard.worsenings() == 0)
    }

    /// The clock read is the whole cost the reports add to the candidate loop,
    /// so the read count is the candidate count whatever the reports do.
    @Test func readsTheClockOnceForEachCandidate() {
        let source = aSmallSample()

        let often = run(source, steppingBy: LayoutProgress.reportInterval)
        let seldom = run(source, steppingBy: LayoutProgress.reportInterval / 20)

        #expect(often.clock.reads() == seldom.clock.reads())
        #expect(often.heard.count() <= often.clock.reads() + 1)
        #expect(often.heard.count() > seldom.heard.count())
    }

    /// A search nobody listens to reads no clock at all, so the reports cost a
    /// search with no preview nothing.
    @Test func readsNoClockWhenNobodyListens() {
        let clock = SteppingClock(step: LayoutProgress.reportInterval)

        _ = LayOutModel(now: { clock.reading() })
            .execute(LayOutModelRequest(source: aSmallSample()))

        #expect(clock.reads() == 0)
    }
}

/// A clock that moves one step on every reading, so a test states the search's
/// own time without waiting for a real one.
private final class SteppingClock: @unchecked Sendable {
    private let lock = NSLock()
    private let step: TimeInterval
    private var seconds: TimeInterval = 0
    private var readings = 0

    init(step: TimeInterval) { self.step = step }

    func reading() -> TimeInterval {
        lock.lock()
        defer { lock.unlock() }
        readings += 1
        seconds += step
        return seconds
    }

    /// The time the readings have run through, without moving the clock on.
    func elapsed() -> TimeInterval {
        lock.lock()
        defer { lock.unlock() }
        return seconds
    }

    func reads() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return readings
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
