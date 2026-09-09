import Foundation
import Testing
@testable import threatmodeller

/// What the coalescer ran, so a test reads it after an await.
@MainActor
private final class Recorder {
    var runs = 0
    var last = ""
}

/// Waits for what the coalescer does, rather than for a length of time, so a
/// busy machine does not fail a test that is not about time.
@MainActor
private func waitUntil(_ isReady: @MainActor () -> Bool) async {
    for _ in 0 ..< 400 {
        if isReady() { return }
        try? await Task.sleep(for: .milliseconds(10))
    }
}

/// The coalescer joins a burst of changes into one piece of work.
///
/// Every test here uses a wait far shorter than the one the application uses,
/// so the suite stays fast.
@MainActor
struct TimerCoalescerTests {
    private let wait = 0.02

    @Test func runsTheWorkAfterTheWait() async {
        let coalescer = TimerCoalescer(wait: wait)
        let recorder = Recorder()

        coalescer.schedule { recorder.runs += 1 }
        #expect(recorder.runs == 0)
        await waitUntil { recorder.runs > 0 }

        #expect(recorder.runs == 1)
    }

    @Test func runsTheWorkOnceForABurst() async {
        let coalescer = TimerCoalescer(wait: wait)
        let recorder = Recorder()

        for _ in 0 ..< 5 { coalescer.schedule { recorder.runs += 1 } }
        await waitUntil { recorder.runs > 0 }
        // Long enough for a second run to arrive, if the coalescer let one.
        try? await Task.sleep(for: .milliseconds(100))

        #expect(recorder.runs == 1)
    }

    @Test func runsTheLastWorkItWasGiven() async {
        let coalescer = TimerCoalescer(wait: wait)
        let recorder = Recorder()

        coalescer.schedule { recorder.last = "first" }
        coalescer.schedule { recorder.last = "second" }
        await waitUntil { recorder.last.isEmpty == false }

        #expect(recorder.last == "second")
    }

    @Test func runsNothingAfterACancel() async {
        let coalescer = TimerCoalescer(wait: wait)
        let recorder = Recorder()

        coalescer.schedule { recorder.runs += 1 }
        coalescer.cancel()
        try? await Task.sleep(for: .milliseconds(100))

        #expect(recorder.runs == 0)
    }
}
