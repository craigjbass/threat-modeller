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
    /// The new identifiers, so the canvas can select what was just pasted, and
    /// the controls this catalogue does not hold, so the delivery mechanism
    /// can say what the paste dropped.
    case pasted(componentIds: [String], zoneIds: [String], droppedControls: [String] = [])
    case nothingToPaste
    case unreadable(reason: String)
}

/// Puts a copied selection back onto the model.
///
/// Every identifier is fresh and the copied links are rewritten onto them:
/// identifiers are unique within one document and the clipboard crosses
/// documents. The paste is offset so the copy is visibly not the original.
///
/// The user's answers come along: the controls they ticked, the severities they
/// overrode and the likelihood they found are read onto the fresh identifiers,
/// so a pasted element scores what the copied one scored. A control this
/// catalogue does not hold is dropped and named in the response, because the
/// clipboard crosses documents and a document names its own catalogue.
///
/// An answer the model already holds for the same key wins, so pasting into
/// the document the copy came from changes no answer that is already there.
public struct PasteSelection: PasteSelectionUseCase {
    /// Far enough to see, near enough to still be beside the original.
    public static let defaultOffset = 40.0

    private let models: ThreatModelGateway
    private let ids: IdentityGenerator
    private let files: ThreatModelFileGateway
    private let catalogue: TechnologyCatalogue

    public init(
        models: ThreatModelGateway,
        ids: IdentityGenerator,
        files: ThreatModelFileGateway,
        catalogue: TechnologyCatalogue
    ) {
        self.models = models
        self.ids = ids
        self.files = files
        self.catalogue = catalogue
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

        return models.mutate(label: ChangeLabel.paste) { model in
            model.components.append(contentsOf: placed.components)
            model.connections.append(contentsOf: placed.connections)
            model.zones.append(contentsOf: placed.zones)

            let dropped = SelectionAnswerMerge.merge(
                placed,
                into: &model,
                catalogue: catalogue
            )

            return .pasted(
                componentIds: placed.components.map(\.id.value),
                zoneIds: placed.zones.map(\.id.value),
                droppedControls: dropped.map(\.value).sorted()
            )
        }
    }
}

/// Writes a placed selection's answers onto a model.
///
/// One rule for pasting and for duplicating: an answer the model already holds
/// stands, and a control this catalogue does not hold is dropped and named.
enum SelectionAnswerMerge {
    /// The control keys dropped, because this catalogue words no such control.
    @discardableResult
    static func merge(
        _ placed: SelectionSnippet,
        into model: inout ThreatModel,
        catalogue: TechnologyCatalogue
    ) -> [ControlKey] {
        let known = ControlKeyPruning.wordings(of: model, catalogue: catalogue)
        var dropped: [ControlKey] = []

        for (key, status) in placed.controlStatuses {
            guard ControlKeyPruning.isReachable(key, wordings: known) else {
                dropped.append(key)
                continue
            }
            if model.controlStatuses[key] == nil {
                model.controlStatuses[key] = status
            }
        }
        for (key, severityId) in placed.severityOverrides where model.severityOverrides[key] == nil {
            model.severityOverrides[key] = severityId
        }
        for (key, finding) in placed.likelihoodFindings where model.likelihoodFindings[key] == nil {
            model.likelihoodFindings[key] = finding
        }

        return dropped
    }
}

/// Gives a copied selection fresh identifiers and a new place to sit.
///
/// Shared by pasting and duplicating, which differ only in where the selection
/// came from. Every field of every element comes along, and so do the user's
/// answers: a pasted element that scored differently from the one copied would
/// be a different element.
enum SelectionPlacement {
    static func place(
        _ snippet: SelectionSnippet,
        offsetX: Double,
        offsetY: Double,
        ids: IdentityGenerator
    ) -> SelectionSnippet {
        var componentIds: [ComponentId: ComponentId] = [:]
        var connectionIds: [ConnectionId: ConnectionId] = [:]
        var zoneIds: [ZoneId: ZoneId] = [:]

        for component in snippet.components {
            componentIds[component.id] = ComponentId(ids.next())
        }
        let components = snippet.components.map { component -> Component in
            Component(
                id: componentIds[component.id] ?? component.id,
                technologyId: component.technologyId,
                position: Point(
                    x: component.position.x + offsetX,
                    y: component.position.y + offsetY
                ),
                sensitivity: component.sensitivity,
                customName: component.customName,
                threatsDisabled: component.threatsDisabled,
                runsAs: component.runsAs,
                assets: component.assets,
                shape: component.shape,
                // A pasted user keeps the reaches and the clients that name
                // a pasted component, under their fresh ids, and drops the
                // rest.
                user: component.user.map { facts in
                    UserFacts(
                        role: facts.role,
                        uses: facts.uses.compactMap { componentIds[ComponentId($0)]?.value },
                        reaches: facts.reaches.compactMap { componentIds[ComponentId($0)]?.value },
                        threatActorId: facts.threatActorId
                    )
                }
            )
        }

        let connections = snippet.connections.compactMap { connection -> Connection? in
            guard let source = componentIds[connection.source],
                  let target = componentIds[connection.target] else { return nil }
            let fresh = ConnectionId(ids.next())
            connectionIds[connection.id] = fresh
            return Connection(
                id: fresh,
                source: source,
                target: target,
                kind: connection.kind,
                description: connection.description
            )
        }

        let zones = snippet.zones.map { zone -> Zone in
            let fresh = ZoneId(ids.next())
            zoneIds[zone.id] = fresh
            return Zone(
                id: fresh,
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
                riskReductionPercent: zone.riskReductionPercent,
                boundary: zone.boundary,
                description: zone.description
            )
        }

        return SelectionSnippet(
            components: components,
            connections: connections,
            zones: zones,
            controlStatuses: Dictionary(
                snippet.controlStatuses.map { (rewritten(control: $0.key, componentIds), $0.value) },
                uniquingKeysWith: { first, _ in first }
            ),
            severityOverrides: Dictionary(
                snippet.severityOverrides.map {
                    (rewritten(override: $0.key, componentIds), $0.value)
                },
                uniquingKeysWith: { first, _ in first }
            ),
            likelihoodFindings: Dictionary(
                snippet.likelihoodFindings.map {
                    (
                        rewritten(
                            finding: $0.key,
                            componentIds: componentIds,
                            connectionIds: connectionIds,
                            zoneIds: zoneIds
                        ),
                        $0.value
                    )
                },
                uniquingKeysWith: { first, _ in first }
            )
        )
    }

    /// A control key on the component it was copied from, read onto the fresh
    /// component. A link key and a zone key are consolidated across the model
    /// and name no element, so both come through unchanged.
    private static func rewritten(
        control key: ControlKey,
        _ componentIds: [ComponentId: ComponentId]
    ) -> ControlKey {
        for (old, fresh) in componentIds {
            let prefix = ControlIdentity.componentPrefix(old)
            guard key.value.hasPrefix(prefix) else { continue }
            return ControlKey(
                ControlIdentity.componentPrefix(fresh) + key.value.dropFirst(prefix.count)
            )
        }
        return key
    }

    private static func rewritten(
        override key: SeverityOverrideKey,
        _ componentIds: [ComponentId: ComponentId]
    ) -> SeverityOverrideKey {
        for (old, fresh) in componentIds {
            let prefix = SeverityOverrideKey.componentPrefix(old)
            guard key.value.hasPrefix(prefix) else { continue }
            return SeverityOverrideKey(
                SeverityOverrideKey.componentPrefix(fresh) + key.value.dropFirst(prefix.count)
            )
        }
        return key
    }

    /// A finding is keyed `{threatId}@{sourceId}`, and the source names one
    /// element, so the key is rewritten on its source alone.
    private static func rewritten(
        finding key: ThreatKey,
        componentIds: [ComponentId: ComponentId],
        connectionIds: [ConnectionId: ConnectionId],
        zoneIds: [ZoneId: ZoneId]
    ) -> ThreatKey {
        var sources: [(String, String)] = []
        for (old, fresh) in componentIds {
            sources.append(("@component:\(old.value)", "@component:\(fresh.value)"))
        }
        for (old, fresh) in connectionIds {
            sources.append(("@connection:\(old.value)", "@connection:\(fresh.value)"))
        }
        for (old, fresh) in zoneIds {
            sources.append(("@zone:\(old.value)", "@zone:\(fresh.value)"))
        }

        for (old, fresh) in sources where key.value.hasSuffix(old) {
            return ThreatKey(key.value.dropLast(old.count) + fresh)
        }
        return key
    }
}
