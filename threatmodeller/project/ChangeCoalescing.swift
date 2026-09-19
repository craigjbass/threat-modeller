import Foundation

/// Joins a burst of changes into one piece of work.
@MainActor
protocol ChangeCoalescing: AnyObject {
    func schedule(_ work: @escaping @MainActor () -> Void)
    func cancel()
}

/// A coalescer that waits on the main actor.
///
/// A name typed into a field is one change for each letter, so a write on every
/// change would write the files ten times for a ten-letter name. Waiting for
/// the changes to stop writes them once.
@MainActor
final class TimerCoalescer: ChangeCoalescing {
    /// How long the changes must stop for before the work runs.
    static let defaultWait = 0.5

    private let wait: TimeInterval
    private var pending: Task<Void, Never>?

    init(wait: TimeInterval = TimerCoalescer.defaultWait) {
        self.wait = wait
    }

    func schedule(_ work: @escaping @MainActor () -> Void) {
        cancel()
        let wait = wait
        pending = Task { @MainActor in
            try? await Task.sleep(for: .seconds(wait))
            guard Task.isCancelled == false else { return }
            work()
        }
    }

    func cancel() {
        pending?.cancel()
        pending = nil
    }
}
