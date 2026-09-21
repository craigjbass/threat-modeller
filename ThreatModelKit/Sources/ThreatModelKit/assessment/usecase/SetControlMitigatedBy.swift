public protocol SetControlMitigatedByUseCase {
    func execute(_ request: SetControlMitigatedByRequest) -> SetControlMitigatedByResponse
}

public struct SetControlMitigatedByRequest: Equatable, Sendable {
    public let controlKey: String
    /// The edge that implements this control, written `<protector>-><protected>`.
    public let edgeId: String
    /// How much this edge takes off this control's threat, or nil to take the
    /// mapping off.
    public let reducesRiskBy: Int?

    public init(controlKey: String, edgeId: String, reducesRiskBy: Int?) {
        self.controlKey = controlKey
        self.edgeId = edgeId
        self.reducesRiskBy = reducesRiskBy
    }
}

public enum SetControlMitigatedByResponse: Equatable, Sendable {
    case recorded
    case unknownEdge
    case outOfRange

    /// Puts what went wrong where a delivery mechanism shows it, or clears it.
    public func describe(into message: inout String?) {
        switch self {
        case .recorded:
            message = nil
        case .unknownEdge:
            message = "This model declares no mitigates edge with that name."
        case .outOfRange:
            message = "How much an edge takes off runs from 0 to 100."
        }
    }
}

/// Records that one `mitigates` edge implements one control, and how much it
/// takes off.
///
/// An edge states what it answers and whether it is in place. How much it is
/// worth is this answer, because the same edge is worth a different amount to
/// each control it stands for. A control may name more than one edge.
public struct SetControlMitigatedBy: SetControlMitigatedByUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetControlMitigatedByRequest) -> SetControlMitigatedByResponse {
        let key = ControlKey(request.controlKey)

        guard let percent = request.reducesRiskBy else {
            return models.mutate(label: ChangeLabel.setControlMitigatedBy) { model in
                model.controlMitigatedBy[key]?.removeAll { $0.edgeId == request.edgeId }
                if model.controlMitigatedBy[key]?.isEmpty == true {
                    model.controlMitigatedBy[key] = nil
                }
                return .recorded
            }
        }

        guard percent >= 0, percent <= 100 else { return .outOfRange }

        let model = models.current()
        guard let edge = model.mitigatesEdges.first(where: { $0.id == request.edgeId }) else {
            return .unknownEdge
        }
        let isLive = edge.effectiveStatus == .live

        return models.mutate(label: ChangeLabel.setControlMitigatedBy) { model in
            var held = model.controlMitigatedBy[key] ?? []
            held.removeAll { $0.edgeId == request.edgeId }
            held.append(ControlMitigation(edgeId: request.edgeId, reducesRiskBy: percent))
            model.controlMitigatedBy[key] = held
            // A proposed edge states work the team has not done, so it puts
            // no control in place. It states what the score would be.
            model.controlStatuses[key] = isLive ? .implemented : .notImplemented
            return .recorded
        }
    }
}
