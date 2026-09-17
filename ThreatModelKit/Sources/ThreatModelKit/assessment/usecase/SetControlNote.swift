public protocol SetControlNoteUseCase {
    func execute(_ request: SetControlNoteRequest) -> SetControlNoteResponse
}

public struct SetControlNoteRequest: Equatable, Sendable {
    public let controlKey: String
    /// What a person wrote about the control. Empty clears it.
    public let note: String

    public init(controlKey: String, note: String) {
        self.controlKey = controlKey
        self.note = note
    }
}

public enum SetControlNoteResponse: Equatable, Sendable {
    case recorded

    /// Puts what went wrong where a delivery mechanism shows it, or clears it.
    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        }
    }
}

/// Records what a person wrote about one control, beside its evidence.
public struct SetControlNote: SetControlNoteUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetControlNoteRequest) -> SetControlNoteResponse {
        let note = request.note.trimmingWhitespace()
        return models.mutate(label: ChangeLabel.setControlNote) { model in
            model.controlNotes[ControlKey(request.controlKey)] = note.isEmpty ? nil : note
            return .recorded
        }
    }
}
