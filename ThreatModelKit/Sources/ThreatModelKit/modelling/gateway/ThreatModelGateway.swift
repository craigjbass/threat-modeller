/// Holds the model currently being edited.
///
/// One gateway serves one model. Call the gateway from one thread only.
/// A use case reads the model with `current()`, changes it, and writes it
/// back with `save(_:)`. The protocol offers no atomic append operation.
/// Two overlapping calls can lose a change. Add an atomic append operation
/// to this protocol before any concurrent caller exists.
public protocol ThreatModelGateway: AnyObject {
    func current() -> ThreatModel
    func save(_ model: ThreatModel)
}

/// The model store for one open document. From Milestone 6 a document seeds it
/// on open and writes it back on save.
public final class InMemoryThreatModelGateway: ThreatModelGateway {
    private var model: ThreatModel

    public init(_ model: ThreatModel = ThreatModel()) {
        self.model = model
    }

    public func current() -> ThreatModel { model }

    public func save(_ model: ThreatModel) { self.model = model }
}
