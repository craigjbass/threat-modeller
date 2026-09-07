/// Holds the model currently being edited.
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
