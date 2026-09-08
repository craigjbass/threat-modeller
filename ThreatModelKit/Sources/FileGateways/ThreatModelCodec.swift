import Foundation
import ThreatModelKit

/// Reads and writes the document format of spec section 8.
///
/// The file is pretty-printed with sorted keys: a threat model is a document a
/// team reviews in a pull request, and a diff of one line should be one line.
public struct ThreatModelCodec: ThreatModelFileGateway {
    /// This application's own format version, separate from the catalogue's.
    public static let formatVersion = 1

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
                customTechnologies: [],
                severityOverrides: Dictionary(
                    uniqueKeysWithValues: model.severityOverrides.map { ($0.key.value, $0.value) }
                ),
                implementedControls: model.implementedControls.map(\.value).sorted(),
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
                )
            )
        )
    }

    public func decode(_ data: Data) throws -> ThreatModel {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let document = try decoder.decode(DocumentJSON.self, from: data)

        guard document.formatVersion == Self.formatVersion else {
            throw ThreatModelFileError.unsupportedFormatVersion(
                found: document.formatVersion,
                supported: Self.formatVersion
            )
        }

        return ThreatModel(
            name: document.name,
            components: try document.components.map(Self.component(from:)),
            connections: document.connections.map(Self.connection(from:)),
            zones: try document.zones.map(Self.zone(from:)),
            severityOverrides: Dictionary(
                uniqueKeysWithValues: document.severityOverrides.map {
                    (SeverityOverrideKey($0.key), $0.value)
                }
            ),
            implementedControls: Set(document.implementedControls.map(ControlKey.init)),
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

        guard snippet.formatVersion == Self.formatVersion else {
            throw ThreatModelFileError.unsupportedFormatVersion(
                found: snippet.formatVersion,
                supported: Self.formatVersion
            )
        }

        return SelectionSnippet(
            components: try snippet.components.map(Self.component(from:)),
            connections: snippet.connections.map(Self.connection(from:)),
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
            threatsDisabled: component.threatsDisabled
        )
    }

    private static func json(from connection: Connection) -> ConnectionJSON {
        ConnectionJSON(
            id: connection.id.value,
            source: connection.source.value,
            target: connection.target.value
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
            riskReductionPercent: zone.riskReductionPercent
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
            threatsDisabled: json.threatsDisabled
        )
    }

    private static func connection(from json: ConnectionJSON) -> Connection {
        Connection(
            id: ConnectionId(json.id),
            source: ComponentId(json.source),
            target: ComponentId(json.target)
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
            riskReductionPercent: json.riskReductionPercent
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
}
