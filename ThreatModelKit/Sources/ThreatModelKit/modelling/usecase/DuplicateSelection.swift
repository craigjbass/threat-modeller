public protocol DuplicateSelectionUseCase {
    func execute(_ request: DuplicateSelectionRequest) -> DuplicateSelectionResponse
}

public struct DuplicateSelectionRequest: Equatable, Sendable {
    public let componentIds: [String]
    public let zoneIds: [String]
    public let offsetX: Double
    public let offsetY: Double

    public init(componentIds: [String], zoneIds: [String], offsetX: Double, offsetY: Double) {
        self.componentIds = componentIds
        self.zoneIds = zoneIds
        self.offsetX = offsetX
        self.offsetY = offsetY
    }
}

public enum DuplicateSelectionResponse: Equatable, Sendable {
    case duplicated(componentIds: [String], zoneIds: [String])
    case nothingSelected
}

/// Copies and pastes in one step, without going near the clipboard: what the
/// user had copied before is still there afterwards.
public struct DuplicateSelection: DuplicateSelectionUseCase {
    private let models: ThreatModelGateway
    private let ids: IdentityGenerator

    public init(models: ThreatModelGateway, ids: IdentityGenerator) {
        self.models = models
        self.ids = ids
    }

    public func execute(_ request: DuplicateSelectionRequest) -> DuplicateSelectionResponse {
        models.mutate { model in
            let snippet = CopySelection.snippet(
                of: model,
                componentIds: request.componentIds,
                zoneIds: request.zoneIds
            )
            guard snippet.isEmpty == false else { return .nothingSelected }

            let placed = SelectionPlacement.place(
                snippet,
                offsetX: request.offsetX,
                offsetY: request.offsetY,
                ids: ids
            )
            model.components.append(contentsOf: placed.components)
            model.connections.append(contentsOf: placed.connections)
            model.zones.append(contentsOf: placed.zones)

            return .duplicated(
                componentIds: placed.components.map(\.id.value),
                zoneIds: placed.zones.map(\.id.value)
            )
        }
    }
}
