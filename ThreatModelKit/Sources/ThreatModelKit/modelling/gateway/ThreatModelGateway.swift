import Foundation

/// Holds the model currently being edited.
///
/// One gateway serves one model. `current()` and `save(_:)` are each atomic,
/// but a use case that reads, changes and writes has a gap between them, and
/// SwiftUI can ask a document for its bytes on a background thread while the
/// main actor is part-way through one. `mutate` closes that gap: every write
/// use case reads, changes and writes in one step.
public protocol ThreatModelGateway: AnyObject, Sendable {
    func current() -> ThreatModel
    func save(_ model: ThreatModel)
    /// Read, change and write without a gap. Returns whatever the change
    /// returns, so a use case can decide its response inside the same step.
    func mutate<T>(_ change: (inout ThreatModel) -> T) -> T
}

/// The model store for one open document. A document seeds it on open and
/// reads it back on save.
///
/// The lock is the whole point: the document's writer runs wherever SwiftUI
/// puts it, and the editor runs on the main actor. `@unchecked Sendable` is
/// stated rather than inferred, because the lock is what makes it safe and the
/// compiler cannot see that.
public final class InMemoryThreatModelGateway: ThreatModelGateway, @unchecked Sendable {
    private let lock = NSLock()
    private var model: ThreatModel

    public init(_ model: ThreatModel = ThreatModel()) {
        self.model = model
    }

    public func current() -> ThreatModel {
        lock.lock()
        defer { lock.unlock() }
        return model
    }

    public func save(_ model: ThreatModel) {
        lock.lock()
        defer { lock.unlock() }
        self.model = model
    }

    public func mutate<T>(_ change: (inout ThreatModel) -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return change(&model)
    }
}
