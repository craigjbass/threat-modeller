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
        let zoneSet = Set(zoneIds.map(ZoneId.init))

        let copiedComponents = model.components.filter { components.contains($0.id) }
        let copiedConnections = model.connections.filter {
            components.contains($0.source) && components.contains($0.target)
        }
        let copiedZones = model.zones.filter { zoneSet.contains($0.id) }

        // The scopes whose answers travel: one per copied component, plus the
        // consolidated link scope and zone scope when a link or a zone is
        // copied. Spec section 5.3 consolidates those two across the model, so
        // a copy that holds one carries the answers that score it.
        let answers = SelectionAnswers(
            componentIds: components,
            carriesConnections: copiedConnections.isEmpty == false,
            carriesZones: copiedZones.isEmpty == false,
            connectionIds: Set(copiedConnections.map(\.id)),
            zoneIds: zoneSet
        )

        return SelectionSnippet(
            components: copiedComponents,
            connections: copiedConnections,
            zones: copiedZones,
            controlStatuses: model.controlStatuses.filter { answers.carries(control: $0.key) },
            severityOverrides: model.severityOverrides.filter { answers.carries(override: $0.key) },
            likelihoodFindings: model.likelihoodFindings.filter { answers.carries(finding: $0.key) }
        )
    }
}

/// Which of a model's answers belong to a copied selection.
struct SelectionAnswers {
    let componentIds: Set<ComponentId>
    let carriesConnections: Bool
    let carriesZones: Bool
    let connectionIds: Set<ConnectionId>
    let zoneIds: Set<ZoneId>

    func carries(control key: ControlKey) -> Bool {
        if componentIds.contains(where: { key.value.hasPrefix(ControlIdentity.componentPrefix($0)) }) {
            return true
        }
        if carriesConnections && key.value.hasPrefix("connection:") { return true }
        if carriesZones && key.value.hasPrefix("zone:") { return true }
        return false
    }

    func carries(override key: SeverityOverrideKey) -> Bool {
        if componentIds.contains(where: {
            key.value.hasPrefix(SeverityOverrideKey.componentPrefix($0))
        }) {
            return true
        }
        if carriesConnections && key.value.hasPrefix("connection::") { return true }
        if carriesZones && key.value.hasPrefix("zone::") { return true }
        return false
    }

    func carries(finding key: ThreatKey) -> Bool {
        let sources = componentIds.map { "@component:\($0.value)" }
            + connectionIds.map { "@connection:\($0.value)" }
            + zoneIds.map { "@zone:\($0.value)" }
        return sources.contains { key.value.hasSuffix($0) }
    }
}
