public protocol SetControlMitigatedByUseCase {
    func execute(_ request: SetControlMitigatedByRequest) -> SetControlMitigatedByResponse
}

public struct SetControlMitigatedByRequest: Equatable, Sendable {
    public let controlKey: String
    /// The edge that implements this control, written `<protector>-><protected>`,
    /// or nil to take the mapping off.
    public let edgeId: String?

    public init(controlKey: String, edgeId: String?) {
        self.controlKey = controlKey
        self.edgeId = edgeId
    }
}

public enum SetControlMitigatedByResponse: Equatable, Sendable {
    case recorded
    case unknownEdge
    case edgeIsAssumed

    /// Puts what went wrong where a delivery mechanism shows it, or clears it.
    public func describe(into message: inout String?) {
        switch self {
        case .recorded:
            message = nil
        case .unknownEdge:
            message = "This model declares no mitigates edge with that name."
        case .edgeIsAssumed:
            message = "That mitigates edge is assumed, so it implements no control yet."
        }
    }
}

/// Records that one `mitigates` edge implements one control.
///
/// An edge lowers a score on its own. It answers a control only when a person
/// says it does, which is what this writes. An assumed edge states work the
/// team has not done, so it implements nothing.
public struct SetControlMitigatedBy: SetControlMitigatedByUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetControlMitigatedByRequest) -> SetControlMitigatedByResponse {
        let key = ControlKey(request.controlKey)

        guard let edgeId = request.edgeId else {
            return models.mutate(label: ChangeLabel.setControlMitigatedBy) { model in
                model.controlMitigatedBy[key] = nil
                return .recorded
            }
        }

        let model = models.current()
        guard let edge = model.mitigatesEdges.first(where: { $0.id == edgeId }) else {
            return .unknownEdge
        }
        guard edge.effectiveStatus == .adopted else { return .edgeIsAssumed }

        return models.mutate(label: ChangeLabel.setControlMitigatedBy) { model in
            model.controlMitigatedBy[key] = edgeId
            model.controlStatuses[key] = .implemented
            return .recorded
        }
    }
}
