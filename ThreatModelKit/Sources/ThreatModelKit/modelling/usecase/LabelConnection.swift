public protocol LabelConnectionUseCase {
    func execute(_ request: LabelConnectionRequest) -> LabelConnectionResponse
}

public struct LabelConnectionRequest: Equatable, Sendable {
    public let connectionId: String
    /// What the flow is for. An empty text clears the label.
    public let label: String

    public init(connectionId: String, label: String) {
        self.connectionId = connectionId
        self.label = label
    }
}

public enum LabelConnectionResponse: Equatable, Sendable {
    case labelled
    case unknownConnection
}

/// Writes a flow's label.
///
/// The label is the description the connection panel edits: one field, one
/// value, so the canvas and the panel can never show two different things.
/// This use case exists because the canvas edits that one field and nothing
/// else, and a person editing a label on the canvas must not change the flow's
/// kind by accident.
public struct LabelConnection: LabelConnectionUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: LabelConnectionRequest) -> LabelConnectionResponse {
        let id = ConnectionId(request.connectionId)

        return models.mutate(label: ChangeLabel.labelConnection) { model in
            guard let index = model.connections.firstIndex(where: { $0.id == id }) else {
                return .unknownConnection
            }
            let trimmed = request.label.trimmingWhitespace()
            model.connections[index].description = trimmed.isEmpty ? nil : trimmed
            return .labelled
        }
    }
}
