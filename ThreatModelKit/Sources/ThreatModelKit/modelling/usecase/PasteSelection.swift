public protocol PasteSelectionUseCase {
    func execute(_ request: PasteSelectionRequest) -> PasteSelectionResponse
}

public struct PasteSelectionRequest: Equatable, Sendable {
    public let payload: String
    public let offsetX: Double
    public let offsetY: Double

    public init(payload: String, offsetX: Double, offsetY: Double) {
        self.payload = payload
        self.offsetX = offsetX
        self.offsetY = offsetY
    }
}

public enum PasteSelectionResponse: Equatable, Sendable {
    /// The new identifiers, so the canvas can select what was just pasted.
    case pasted(componentIds: [String], zoneIds: [String])
    case nothingToPaste
    case unreadable(reason: String)
}

/// Puts a copied selection back onto the model.
///
/// Every identifier is fresh and the copied links are rewritten onto them:
/// identifiers are unique within one document and the clipboard crosses
/// documents. The paste is offset so the copy is visibly not the original.
///
/// Ticks and overrides do not come along. A control key names a component that
/// no longer exists after the paste, and a severity override is keyed by
/// technology and already applies. Copying a component copies the component,
/// not the user's answers about it.
public struct PasteSelection: PasteSelectionUseCase {
    /// Far enough to see, near enough to still be beside the original.
    public static let defaultOffset = 40.0

    private let models: ThreatModelGateway
    private let ids: IdentityGenerator
    private let files: ThreatModelFileGateway

    public init(models: ThreatModelGateway, ids: IdentityGenerator, files: ThreatModelFileGateway) {
        self.models = models
        self.ids = ids
        self.files = files
    }

    public func execute(_ request: PasteSelectionRequest) -> PasteSelectionResponse {
        let snippet: SelectionSnippet
        do {
            snippet = try files.decodeSelection(request.payload)
        } catch {
            return .unreadable(reason: String(describing: error))
        }
        guard snippet.isEmpty == false else { return .nothingToPaste }

        let placed = SelectionPlacement.place(
            snippet,
            offsetX: request.offsetX,
            offsetY: request.offsetY,
            ids: ids
        )

        return models.mutate { model in
            model.components.append(contentsOf: placed.components)
            model.connections.append(contentsOf: placed.connections)
            model.zones.append(contentsOf: placed.zones)
            return .pasted(
                componentIds: placed.components.map(\.id.value),
                zoneIds: placed.zones.map(\.id.value)
            )
        }
    }
}

/// Gives a copied selection fresh identifiers and a new place to sit.
///
/// Shared by pasting and duplicating, which differ only in where the selection
/// came from.
enum SelectionPlacement {
    static func place(
        _ snippet: SelectionSnippet,
        offsetX: Double,
        offsetY: Double,
        ids: IdentityGenerator
    ) -> SelectionSnippet {
        var componentIds: [ComponentId: ComponentId] = [:]

        let components = snippet.components.map { component -> Component in
            let fresh = ComponentId(ids.next())
            componentIds[component.id] = fresh
            return Component(
                id: fresh,
                technologyId: component.technologyId,
                position: Point(
                    x: component.position.x + offsetX,
                    y: component.position.y + offsetY
                ),
                sensitivity: component.sensitivity,
                customName: component.customName,
                threatsDisabled: component.threatsDisabled
            )
        }

        let connections = snippet.connections.compactMap { connection -> Connection? in
            guard let source = componentIds[connection.source],
                  let target = componentIds[connection.target] else { return nil }
            return Connection(id: ConnectionId(ids.next()), source: source, target: target)
        }

        let zones = snippet.zones.map { zone in
            Zone(
                id: ZoneId(ids.next()),
                rect: Rect(
                    x: zone.rect.origin.x + offsetX,
                    y: zone.rect.origin.y + offsetY,
                    width: zone.rect.size.width,
                    height: zone.rect.size.height
                ),
                name: zone.name,
                networkZone: zone.networkZone,
                networkType: zone.networkType,
                riskReductionEnabled: zone.riskReductionEnabled,
                riskReductionPercent: zone.riskReductionPercent
            )
        }

        return SelectionSnippet(components: components, connections: connections, zones: zones)
    }
}
