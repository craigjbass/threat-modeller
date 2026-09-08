public protocol CopySelectionUseCase {
    func execute(_ request: CopySelectionRequest) -> CopySelectionResponse
}

public struct CopySelectionRequest: Equatable, Sendable {
    public let componentIds: [String]
    public let zoneIds: [String]

    public init(componentIds: [String], zoneIds: [String]) {
        self.componentIds = componentIds
        self.zoneIds = zoneIds
    }
}

public enum CopySelectionResponse: Equatable, Sendable {
    /// Clipboard text, and what it holds, so the delivery mechanism can say
    /// what it copied.
    case copied(payload: String, componentCount: Int, zoneCount: Int)
    case nothingSelected
}

/// Turns what the user selected into clipboard text.
///
/// Only the links whose source and target are both selected come along:
/// pasting a link with one end missing would leave a link to nothing.
public struct CopySelection: CopySelectionUseCase {
    private let models: ThreatModelGateway
    private let files: ThreatModelFileGateway

    public init(models: ThreatModelGateway, files: ThreatModelFileGateway) {
        self.models = models
        self.files = files
    }

    public func execute(_ request: CopySelectionRequest) -> CopySelectionResponse {
        let snippet = Self.snippet(
            of: models.current(),
            componentIds: request.componentIds,
            zoneIds: request.zoneIds
        )
        guard snippet.isEmpty == false else { return .nothingSelected }

        do {
            return .copied(
                payload: try files.encodeSelection(snippet),
                componentCount: snippet.components.count,
                zoneCount: snippet.zones.count
            )
        } catch {
            return .nothingSelected
        }
    }

    /// Shared with `DuplicateSelection`, which takes the same slice of a model
    /// without going near the clipboard.
    static func snippet(
        of model: ThreatModel,
        componentIds: [String],
        zoneIds: [String]
    ) -> SelectionSnippet {
        let components = Set(componentIds.map(ComponentId.init))
        let zones = Set(zoneIds.map(ZoneId.init))

        return SelectionSnippet(
            components: model.components.filter { components.contains($0.id) },
            connections: model.connections.filter {
                components.contains($0.source) && components.contains($0.target)
            },
            zones: model.zones.filter { zones.contains($0.id) }
        )
    }
}
