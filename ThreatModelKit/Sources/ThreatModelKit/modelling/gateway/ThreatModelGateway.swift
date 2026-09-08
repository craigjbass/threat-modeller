import Foundation

/// Holds the model currently being edited.
///
/// One gateway serves one model. `current()` and `save(_:)` are each atomic,
/// but a use case that reads, changes and writes has a gap between them, and
/// SwiftUI can ask a document for its bytes on a background thread while the
/// main actor is part-way through one. `mutate` closes that gap: every write
/// use case reads, changes and writes in one step.
///
/// `mutate` also records history. The snapshot is taken inside it, before the
/// change, and kept only when the model actually changed: one use case is one
/// undo step, no use case can forget to record one, and a refused change is
/// not a step. `save(_:)` clears the history instead — replacing the model
/// outright is opening a different document, not a change to take back.
public protocol ThreatModelGateway: AnyObject, Sendable {
    func current() -> ThreatModel
    func save(_ model: ThreatModel)
    /// Read, change and write without a gap. Returns whatever the change
    /// returns, so a use case can decide its response inside the same step.
    func mutate<T>(_ change: (inout ThreatModel) -> T) -> T
    /// Takes the model back one change. Returns false when there is nothing to
    /// take back.
    func undo() -> Bool
    /// Puts back a change that was taken back. Returns false when there is
    /// nothing to put back.
    func redo() -> Bool
    var canUndo: Bool { get }
    var canRedo: Bool { get }
}

/// The model store for one open document. A document seeds it on open and
/// reads it back on save.
///
/// The lock is the whole point: the document's writer runs wherever SwiftUI
/// puts it, and the editor runs on the main actor. `@unchecked Sendable` is
/// stated rather than inferred, because the lock is what makes it safe and the
/// compiler cannot see that.
public final class InMemoryThreatModelGateway: ThreatModelGateway, @unchecked Sendable {
    /// How far back the user can go. Deep enough that nobody reaches it in a
    /// session, shallow enough that a long session does not grow without end.
    public static let historyLimit = 100

    private let lock = NSLock()
    private var model: ThreatModel
    private var past: [ThreatModel] = []
    private var future: [ThreatModel] = []

    public init(_ model: ThreatModel = ThreatModel()) {
        self.model = model
    }

    public func current() -> ThreatModel {
        lock.lock()
        defer { lock.unlock() }
        return model
    }

    /// Replaces the model and forgets the history. Only `CreateThreatModel` and
    /// `OpenThreatModel` call this.
    public func save(_ model: ThreatModel) {
        lock.lock()
        defer { lock.unlock() }
        self.model = model
        past = []
        future = []
    }

    public func mutate<T>(_ change: (inout ThreatModel) -> T) -> T {
        lock.lock()
        defer { lock.unlock() }

        let before = model
        let result = change(&model)

        if model != before {
            past.append(before)
            if past.count > Self.historyLimit { past.removeFirst() }
            // The user has taken a different branch. Offering to redo the
            // abandoned one would be a lie.
            future = []
        }

        return result
    }

    public func undo() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let previous = past.popLast() else { return false }
        future.append(model)
        model = previous
        return true
    }

    public func redo() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let next = future.popLast() else { return false }
        past.append(model)
        model = next
        return true
    }

    public var canUndo: Bool {
        lock.lock()
        defer { lock.unlock() }
        return past.isEmpty == false
    }

    public var canRedo: Bool {
        lock.lock()
        defer { lock.unlock() }
        return future.isEmpty == false
    }
}
