public protocol SetSystemDiagramUseCase {
    func execute(_ request: SetSystemDiagramRequest) -> SetSystemDiagramResponse
}

public struct SetSystemDiagramRequest: Equatable, Sendable {
    /// Names the diagram. Writing the same label again changes the block
    /// that is there.
    public let label: String
    /// A kind id: `mermaid` or `d2`.
    public let kind: String
    public let text: String

    public init(label: String, kind: String = "mermaid", text: String) {
        self.label = label
        self.kind = kind
        self.text = text
    }
}

public enum SetSystemDiagramResponse: Equatable, Sendable {
    case recorded
    case noLabel
    case noText
    case unknownKind

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .noLabel: message = "A diagram needs a label."
        case .noText: message = "A diagram needs mermaid text."
        case .unknownKind: message = "A diagram's kind is mermaid or d2."
        }
    }
}

/// Writes one `diagram` block: one picture a team keeps beside the diagram
/// the canvas draws.
///
/// The label names it, so writing the same label again changes the block that
/// is there rather than adding a second. Mermaid and D2 are the kinds this
/// application draws.
public struct SetSystemDiagram: SetSystemDiagramUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetSystemDiagramRequest) -> SetSystemDiagramResponse {
        let label = request.label.trimmingWhitespace()
        let text = request.text.trimmingWhitespace()

        guard label.isEmpty == false else { return .noLabel }
        guard text.isEmpty == false else { return .noText }
        guard let kind = DiagramKind(rawValue: request.kind.trimmingWhitespace()) else {
            return .unknownKind
        }

        return models.mutate(label: ChangeLabel.setSystemDiagram) { model in
            let written = SystemDiagram(label: label, kind: kind.rawValue, text: text)
            if let already = model.diagrams.firstIndex(where: { $0.label == label }) {
                model.diagrams[already] = written
            } else {
                model.diagrams.append(written)
            }
            return .recorded
        }
    }
}

public protocol RemoveSystemDiagramUseCase {
    func execute(_ request: RemoveSystemDiagramRequest) -> RemoveSystemDiagramResponse
}

public struct RemoveSystemDiagramRequest: Equatable, Sendable {
    public let label: String

    public init(label: String) {
        self.label = label
    }
}

public enum RemoveSystemDiagramResponse: Equatable, Sendable {
    case removed
    case noSuchDiagram

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .noSuchDiagram: message = "This system holds no such diagram."
        }
    }
}

/// Takes a `diagram` block off the system.
public struct RemoveSystemDiagram: RemoveSystemDiagramUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveSystemDiagramRequest) -> RemoveSystemDiagramResponse {
        let label = request.label.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.removeSystemDiagram) { model in
            guard let found = model.diagrams.firstIndex(where: { $0.label == label }) else {
                return .noSuchDiagram
            }
            model.diagrams.remove(at: found)
            return .removed
        }
    }
}
