public protocol SetMitigatesEdgeUseCase {
    func execute(_ request: SetMitigatesEdgeRequest) -> SetMitigatesEdgeResponse
}

public struct SetMitigatesEdgeRequest: Equatable, Sendable {
    /// What a team would do to put a proposed edge in place.
    public struct Action: Equatable, Sendable {
        public let label: String
        public let text: String?
        public let note: String?
        /// An assumption label declared in the same system, or nil.
        public let blockedBy: String?
        public let sources: [String]

        public init(
            label: String,
            text: String? = nil,
            note: String? = nil,
            blockedBy: String? = nil,
            sources: [String] = []
        ) {
            self.label = label
            self.text = text
            self.note = note
            self.blockedBy = blockedBy
            self.sources = sources
        }
    }

    public let sourceComponentId: String
    public let targetComponentId: String
    public let threatIds: [String]
    /// `live` or `proposed`.
    public let status: String
    public let action: Action?

    public init(
        sourceComponentId: String,
        targetComponentId: String,
        threatIds: [String],
        status: String,
        action: Action? = nil
    ) {
        self.sourceComponentId = sourceComponentId
        self.targetComponentId = targetComponentId
        self.threatIds = threatIds
        self.status = status
        self.action = action
    }
}

public enum SetMitigatesEdgeResponse: Equatable, Sendable {
    case recorded
    /// The edge stands, and the action it named does not: only a proposed
    /// edge carries one.
    case recordedWithoutTheAction
    case noThreats
    case unknownStatus
    case unknownComponent
    case selfEdge

    public func describe(into message: inout String?) {
        switch self {
        case .recorded:
            message = nil
        case .recordedWithoutTheAction:
            message = "A live edge carries no recommendation, so that one was dropped."
        case .noThreats:
            message = "A mitigates edge names the threats it lowers."
        case .unknownStatus:
            message = "A mitigates edge is \"live\" or \"proposed\"."
        case .unknownComponent:
            message = "That component is no longer on the model."
        case .selfEdge:
            message = "A component does not lower a threat on itself."
        }
    }
}

/// States that one component lowers a named threat set on another.
///
/// Language guide section 4.8. The two ends name the edge, the way they name a
/// flow, so writing between the same two ends changes the edge that is there.
///
/// An assumed edge states a mitigation the team plans and has not put in
/// place, and only an assumed edge carries a recommendation: an adopted one
/// has no leverage left to claim, because its reduction is already in the
/// residual score.
public struct SetMitigatesEdge: SetMitigatesEdgeUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetMitigatesEdgeRequest) -> SetMitigatesEdgeResponse {
        let source = ComponentId(request.sourceComponentId)
        let target = ComponentId(request.targetComponentId)

        guard source != target else { return .selfEdge }

        let threats = request.threatIds
            .map { $0.trimmingWhitespace() }
            .filter { $0.isEmpty == false }
        guard threats.isEmpty == false else { return .noThreats }
        guard let status = ComponentStatus(rawValue: request.status) else {
            return .unknownStatus
        }

        return models.mutate(label: ChangeLabel.setMitigatesEdge) { model in
            guard model.components.contains(where: { $0.id == source }),
                  model.components.contains(where: { $0.id == target }) else {
                return .unknownComponent
            }

            let carried = status == .proposed ? request.action : nil
            let written = MitigatesEdge(
                source: source,
                target: target,
                threatIds: threats.map(ThreatId.init),
                status: status,
                action: carried.map {
                    EdgeAction(
                        label: $0.label,
                        text: $0.text,
                        note: $0.note,
                        blockedBy: $0.blockedBy,
                        sources: $0.sources
                    )
                }
            )

            if let already = model.mitigatesEdges.firstIndex(
                where: { $0.source == source && $0.target == target }
            ) {
                model.mitigatesEdges[already] = written
            } else {
                model.mitigatesEdges.append(written)
            }

            return request.action != nil && carried == nil ? .recordedWithoutTheAction : .recorded
        }
    }
}

public protocol RemoveMitigatesEdgeUseCase {
    func execute(_ request: RemoveMitigatesEdgeRequest) -> RemoveMitigatesEdgeResponse
}

public struct RemoveMitigatesEdgeRequest: Equatable, Sendable {
    public let sourceComponentId: String
    public let targetComponentId: String

    public init(sourceComponentId: String, targetComponentId: String) {
        self.sourceComponentId = sourceComponentId
        self.targetComponentId = targetComponentId
    }
}

public enum RemoveMitigatesEdgeResponse: Equatable, Sendable {
    case removed
    case noSuchEdge

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .noSuchEdge: message = "No mitigates edge runs between those two."
        }
    }
}

public struct RemoveMitigatesEdge: RemoveMitigatesEdgeUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveMitigatesEdgeRequest) -> RemoveMitigatesEdgeResponse {
        let source = ComponentId(request.sourceComponentId)
        let target = ComponentId(request.targetComponentId)

        return models.mutate(label: ChangeLabel.setMitigatesEdge) { model in
            guard let found = model.mitigatesEdges.firstIndex(
                where: { $0.source == source && $0.target == target }
            ) else {
                return .noSuchEdge
            }
            model.mitigatesEdges.remove(at: found)
            return .removed
        }
    }
}
