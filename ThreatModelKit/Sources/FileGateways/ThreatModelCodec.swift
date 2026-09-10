import Foundation
import ThreatModelKit

/// Reads and writes the document format of spec section 8.
///
/// The file is pretty-printed with sorted keys: a threat model is a document a
/// team reviews in a pull request, and a diff of one line should be one line.
public struct ThreatModelCodec: ThreatModelFileGateway {
    /// This application's own format version, separate from the catalogue's.
    ///
    /// Version 2 adds the technologies a model defines for itself. Version 3
    /// adds a status per control and the compensating controls. An older file
    /// has neither, and its recorded controls become `implemented` statuses,
    /// so a user's saved work does not stop opening. Version 4 adds a flow's
    /// kind and description, a component's privilege and assets, a zone's
    /// boundary and description, the mitigates edges and the recommendations.
    public static let formatVersion = 4
    private static let readableFormatVersions: Set<Int> = [1, 2, 3, 4]

    public init() {}

    public func encode(_ model: ThreatModel) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        return try encoder.encode(
            DocumentJSON(
                formatVersion: Self.formatVersion,
                name: model.name,
                createdAt: model.createdAt,
                updatedAt: model.updatedAt,
                catalogue: model.catalogueVersion.map {
                    CatalogueStampJSON(repository: $0.repository, tag: $0.tag)
                },
                components: model.components.map(Self.json(from:)),
                connections: model.connections.map(Self.json(from:)),
                zones: model.zones.map(Self.json(from:)),
                customTechnologies: model.customTechnologies.map(Self.json(from:)),
                severityOverrides: Dictionary(
                    uniqueKeysWithValues: model.severityOverrides.map { ($0.key.value, $0.value) }
                ),
                implementedControls: model.implementedControls.map(\.value).sorted(),
                controlStatuses: Dictionary(
                    uniqueKeysWithValues: model.controlStatuses.map { ($0.key.value, $0.value.rawValue) }
                ),
                compensatingControls: Dictionary(
                    uniqueKeysWithValues: model.compensatingControls.map { key, controls in
                        (
                            key.value,
                            controls.map {
                                CompensatingControlJSON(
                                    label: $0.label,
                                    reducesRiskBy: $0.reducesRiskBy,
                                    rationale: $0.rationale
                                )
                            }
                        )
                    }
                ),
                pathwayMitigations: PathwayMitigationsJSON(
                    isMasterEnabled: model.pathwayMitigations.isMasterEnabled,
                    configs: Dictionary(
                        uniqueKeysWithValues: model.pathwayMitigations.configs.map {
                            (
                                $0.key.value,
                                PathwayMitigationConfigJSON(
                                    isEnabled: $0.value.isEnabled,
                                    mode: $0.value.mode.rawValue,
                                    reductionPercent: $0.value.reductionPercent
                                )
                            )
                        }
                    )
                ),
                mitigatesEdges: model.mitigatesEdges.map {
                    MitigatesEdgeJSON(
                        source: $0.source.value,
                        target: $0.target.value,
                        threatIds: $0.threatIds.map(\.value),
                        reducesRiskBy: $0.reducesRiskBy
                    )
                },
                recommendations: Dictionary(
                    uniqueKeysWithValues: model.recommendations.map { key, recommendations in
                        (
                            key.value,
                            recommendations.map {
                                RecommendationJSON(text: $0.text, note: $0.note)
                            }
                        )
                    }
                )
            )
        )
    }

    public func decode(_ data: Data) throws -> ThreatModel {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let document = try decoder.decode(DocumentJSON.self, from: data)

        guard Self.readableFormatVersions.contains(document.formatVersion) else {
            throw ThreatModelFileError.unsupportedFormatVersion(
                found: document.formatVersion,
                supported: Self.formatVersion
            )
        }

        return ThreatModel(
            name: document.name,
            components: try document.components.map(Self.component(from:)),
            connections: try document.connections.map(Self.connection(from:)),
            zones: try document.zones.map(Self.zone(from:)),
            severityOverrides: Dictionary(
                uniqueKeysWithValues: document.severityOverrides.map {
                    (SeverityOverrideKey($0.key), $0.value)
                }
            ),
            implementedControls: Set(document.implementedControls.map(ControlKey.init)),
            controlStatuses: Dictionary(
                uniqueKeysWithValues: (document.controlStatuses ?? [:]).compactMap { key, raw in
                    ControlStatus(rawValue: raw).map { (ControlKey(key), $0) }
                }
            ),
            compensatingControls: Dictionary(
                uniqueKeysWithValues: (document.compensatingControls ?? [:]).map { key, controls in
                    (
                        ThreatKey(key),
                        controls.map {
                            CompensatingControl(
                                label: $0.label,
                                reducesRiskBy: $0.reducesRiskBy,
                                rationale: $0.rationale
                            )
                        }
                    )
                }
            ),
            mitigatesEdges: (document.mitigatesEdges ?? []).map {
                MitigatesEdge(
                    source: ComponentId($0.source),
                    target: ComponentId($0.target),
                    threatIds: $0.threatIds.map(ThreatId.init),
                    reducesRiskBy: $0.reducesRiskBy
                )
            },
            recommendations: Dictionary(
                uniqueKeysWithValues: (document.recommendations ?? [:]).map { key, recommendations in
                    (
                        ThreatKey(key),
                        recommendations.map {
                            Recommendation(text: $0.text, note: $0.note)
                        }
                    )
                }
            ),
            pathwayMitigations: PathwayMitigationSettings(
                isMasterEnabled: document.pathwayMitigations.isMasterEnabled,
                configs: Dictionary(
                    uniqueKeysWithValues: try document.pathwayMitigations.configs.map { id, config in
                        (
                            PathwayMitigationId(id),
                            PathwayMitigationConfig(
                                isEnabled: config.isEnabled,
                                mode: try Self.value(
                                    PathwayMitigationMode(rawValue: config.mode),
                                    field: "mode",
                                    raw: config.mode
                                ),
                                reductionPercent: config.reductionPercent
                            )
                        )
                    }
                )
            ),
            customTechnologies: document.customTechnologies.map(Self.customTechnology(from:)),
            createdAt: document.createdAt,
            updatedAt: document.updatedAt,
            catalogueVersion: document.catalogue.map {
                CatalogueVersion(repository: $0.repository, tag: $0.tag)
            }
        )
    }

    public func encodeSelection(_ selection: SelectionSnippet) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        let data = try encoder.encode(
            SelectionJSON(
                formatVersion: Self.formatVersion,
                components: selection.components.map(Self.json(from:)),
                connections: selection.connections.map(Self.json(from:)),
                zones: selection.zones.map(Self.json(from:))
            )
        )
        return String(decoding: data, as: UTF8.self)
    }

    public func decodeSelection(_ text: String) throws -> SelectionSnippet {
        let snippet = try JSONDecoder().decode(SelectionJSON.self, from: Data(text.utf8))

        guard Self.readableFormatVersions.contains(snippet.formatVersion) else {
            throw ThreatModelFileError.unsupportedFormatVersion(
                found: snippet.formatVersion,
                supported: Self.formatVersion
            )
        }

        return SelectionSnippet(
            components: try snippet.components.map(Self.component(from:)),
            connections: try snippet.connections.map(Self.connection(from:)),
            zones: try snippet.zones.map(Self.zone(from:))
        )
    }

    // MARK: one value at a time, shared by the document and the snippet

    private static func json(from component: ThreatModelKit.Component) -> ComponentJSON {
        ComponentJSON(
            id: component.id.value,
            technologyId: component.technologyId.value,
            x: component.position.x,
            y: component.position.y,
            sensitivity: component.sensitivity.rawValue,
            customName: component.customName,
            threatsDisabled: component.threatsDisabled,
            runsAs: component.runsAs.rawValue,
            assets: component.assets.map {
                AssetJSON(name: $0.name, sensitivity: $0.sensitivity.rawValue)
            }
        )
    }

    private static func json(from technology: CustomTechnology) -> CustomTechnologyJSON {
        CustomTechnologyJSON(
            id: technology.id.value,
            name: technology.name,
            category: technology.category.value,
            description: technology.description,
            threatIds: technology.threatIds.map(\.value),
            enforcesEncryption: technology.enforcesEncryption
        )
    }

    private static func customTechnology(from json: CustomTechnologyJSON) -> CustomTechnology {
        CustomTechnology(
            id: TechnologyId(json.id),
            name: json.name,
            category: CategoryId(json.category),
            description: json.description,
            threatIds: json.threatIds.map(ThreatId.init),
            enforcesEncryption: json.enforcesEncryption
        )
    }

    private static func json(from connection: Connection) -> ConnectionJSON {
        ConnectionJSON(
            id: connection.id.value,
            source: connection.source.value,
            target: connection.target.value,
            kind: connection.kind.rawValue,
            description: connection.description
        )
    }

    private static func json(from zone: Zone) -> ZoneJSON {
        ZoneJSON(
            id: zone.id.value,
            x: zone.rect.origin.x,
            y: zone.rect.origin.y,
            width: zone.rect.size.width,
            height: zone.rect.size.height,
            name: zone.name,
            networkZone: zone.networkZone.rawValue,
            networkType: zone.networkType.rawValue,
            riskReductionEnabled: zone.riskReductionEnabled,
            riskReductionPercent: zone.riskReductionPercent,
            boundary: zone.boundary.rawValue,
            description: zone.description
        )
    }

    private static func component(from json: ComponentJSON) throws -> ThreatModelKit.Component {
        ThreatModelKit.Component(
            id: ComponentId(json.id),
            technologyId: TechnologyId(json.technologyId),
            position: Point(x: json.x, y: json.y),
            sensitivity: try value(
                DataSensitivity(rawValue: json.sensitivity),
                field: "sensitivity",
                raw: json.sensitivity
            ),
            customName: json.customName,
            threatsDisabled: json.threatsDisabled,
            runsAs: try optionalValue(PrivilegeLevel.self, field: "runsAs", raw: json.runsAs, default: .default),
            assets: (json.assets ?? []).map {
                Asset(
                    name: $0.name,
                    sensitivity: DataSensitivity(rawValue: $0.sensitivity) ?? .internalData
                )
            }
        )
    }

    private static func connection(from json: ConnectionJSON) throws -> Connection {
        Connection(
            id: ConnectionId(json.id),
            source: ComponentId(json.source),
            target: ComponentId(json.target),
            kind: try optionalValue(FlowKind.self, field: "kind", raw: json.kind, default: .default),
            description: json.description
        )
    }

    private static func zone(from json: ZoneJSON) throws -> Zone {
        Zone(
            id: ZoneId(json.id),
            rect: Rect(x: json.x, y: json.y, width: json.width, height: json.height),
            name: json.name,
            networkZone: try value(
                NetworkZone(rawValue: json.networkZone),
                field: "networkZone",
                raw: json.networkZone
            ),
            networkType: try value(
                ZoneNetworkType(rawValue: json.networkType),
                field: "networkType",
                raw: json.networkType
            ),
            riskReductionEnabled: json.riskReductionEnabled,
            riskReductionPercent: json.riskReductionPercent,
            boundary: try optionalValue(ZoneBoundary.self, field: "boundary", raw: json.boundary, default: .default),
            description: json.description
        )
    }

    /// A vocabulary value this application does not hold is refused by name, so
    /// the message says which field and which value rather than "corrupt file".
    private static func value<T>(_ decoded: T?, field: String, raw: String) throws -> T {
        guard let decoded else {
            throw ThreatModelFileError.unknownValue(field: field, value: raw)
        }
        return decoded
    }

    /// A field added after version 1: an absent value takes the default, the
    /// way every field this format has ever added does. A present value this
    /// application does not hold is refused by name, the same as `value`
    /// refuses one of its older, required neighbours.
    private static func optionalValue<T: RawRepresentable>(
        _ type: T.Type,
        field: String,
        raw: String?,
        default fallback: T
    ) throws -> T where T.RawValue == String {
        guard let raw else { return fallback }
        guard let decoded = T(rawValue: raw) else {
            throw ThreatModelFileError.unknownValue(field: field, value: raw)
        }
        return decoded
    }
}
