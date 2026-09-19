public protocol SetAssumptionUseCase {
    func execute(_ request: SetAssumptionRequest) -> SetAssumptionResponse
}

public struct SetAssumptionRequest: Equatable, Sendable {
    /// Names the assumption. Writing the same label again changes the one
    /// that is there.
    public let label: String
    public let text: String
    public let owner: String?

    public init(label: String, text: String, owner: String? = nil) {
        self.label = label
        self.text = text
        self.owner = owner
    }
}

public enum SetAssumptionResponse: Equatable, Sendable {
    case recorded
    case noLabel
    case noText

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .noLabel: message = "An assumption needs a label."
        case .noText: message = "An assumption needs to say something."
        }
    }
}

/// Writes down a fact the team accepts without proof.
///
/// Language guide section 4.2. The label names it, so writing the same label
/// again changes what is there rather than adding a second. The report gives
/// every assumption a section, which is why one that says nothing is refused.
public struct SetAssumption: SetAssumptionUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetAssumptionRequest) -> SetAssumptionResponse {
        let label = request.label.trimmingWhitespace()
        let text = request.text.trimmingWhitespace()
        let owner = request.owner?.trimmingWhitespace()

        guard label.isEmpty == false else { return .noLabel }
        guard text.isEmpty == false else { return .noText }

        return models.mutate(label: ChangeLabel.setAssumption) { model in
            let written = SystemAssumption(
                label: label,
                text: text,
                owner: owner?.isEmpty == true ? nil : owner
            )
            if let already = model.assumptions.firstIndex(where: { $0.label == label }) {
                model.assumptions[already] = written
            } else {
                model.assumptions.append(written)
            }
            return .recorded
        }
    }
}

public protocol RemoveAssumptionUseCase {
    func execute(_ request: RemoveAssumptionRequest) -> RemoveAssumptionResponse
}

public struct RemoveAssumptionRequest: Equatable, Sendable {
    public let label: String

    public init(label: String) {
        self.label = label
    }
}

public enum RemoveAssumptionResponse: Equatable, Sendable {
    case removed(unblockedActions: Int)
    case noSuchAssumption

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .noSuchAssumption: message = "This system holds no such assumption."
        }
    }

    /// What the window says about the actions the removal unblocked.
    public var unblockedActionsNote: String? {
        guard case .removed(let actions) = self, actions > 0 else { return nil }
        if actions == 1 {
            return "One recommendation no longer waits on that assumption."
        }
        return "\(actions) recommendations no longer wait on that assumption."
    }
}

/// Takes an assumption off the system, and takes the blocker off every edge
/// action that names it.
public struct RemoveAssumption: RemoveAssumptionUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveAssumptionRequest) -> RemoveAssumptionResponse {
        let label = request.label.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.removeAssumption) { model in
            guard let found = model.assumptions.firstIndex(where: { $0.label == label }) else {
                return .noSuchAssumption
            }
            model.assumptions.remove(at: found)
            return .removed(unblockedActions: Self.unblock(label, in: &model))
        }
    }

    private static func unblock(_ label: String, in model: inout ThreatModel) -> Int {
        var unblocked = 0
        for index in model.mitigatesEdges.indices {
            guard let action = model.mitigatesEdges[index].action,
                  action.blockedBy == label else { continue }
            model.mitigatesEdges[index].action = EdgeAction(
                label: action.label,
                text: action.text,
                note: action.note,
                blockedBy: nil,
                sources: action.sources
            )
            unblocked += 1
        }
        return unblocked
    }
}
