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
                components: model.components.map {
                    ComponentJSON(
                        id: $0.id.value,
                        technologyId: $0.technologyId.value,
                        x: $0.position.x,
                        y: $0.position.y,
                        sensitivity: $0.sensitivity.rawValue,
                        customName: $0.customName,
                        threatsDisabled: $0.threatsDisabled
                    )
                },
                connections: model.connections.map {
                    ConnectionJSON(id: $0.id.value, source: $0.source.value, target: $0.target.value)
                },
                zones: model.zones.map {
                    ZoneJSON(
                        id: $0.id.value,
                        x: $0.rect.origin.x,
                        y: $0.rect.origin.y,
                        width: $0.rect.size.width,
                        height: $0.rect.size.height,
                        name: $0.name,
                        networkZone: $0.networkZone.rawValue,
                        networkType: $0.networkType.rawValue,
                        riskReductionEnabled: $0.riskReductionEnabled,
                        riskReductionPercent: $0.riskReductionPercent
                    )
                },
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
            components: try document.components.map { component in
                ThreatModelKit.Component(
                    id: ComponentId(component.id),
                    technologyId: TechnologyId(component.technologyId),
                    position: Point(x: component.x, y: component.y),
                    sensitivity: try Self.value(
                        DataSensitivity(rawValue: component.sensitivity),
                        field: "sensitivity",
                        raw: component.sensitivity
                    ),
                    customName: component.customName,
                    threatsDisabled: component.threatsDisabled
                )
            },
            connections: document.connections.map {
                Connection(
                    id: ConnectionId($0.id),
                    source: ComponentId($0.source),
                    target: ComponentId($0.target)
                )
            },
            zones: try document.zones.map { zone in
                Zone(
                    id: ZoneId(zone.id),
                    rect: Rect(x: zone.x, y: zone.y, width: zone.width, height: zone.height),
                    name: zone.name,
                    networkZone: try Self.value(
                        NetworkZone(rawValue: zone.networkZone),
                        field: "networkZone",
                        raw: zone.networkZone
                    ),
                    networkType: try Self.value(
                        ZoneNetworkType(rawValue: zone.networkType),
                        field: "networkType",
                        raw: zone.networkType
                    ),
                    riskReductionEnabled: zone.riskReductionEnabled,
                    riskReductionPercent: zone.riskReductionPercent
                )
            },
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

    /// A vocabulary value this application does not hold is refused by name, so
    /// the message says which field and which value rather than "corrupt file".
    private static func value<T>(_ decoded: T?, field: String, raw: String) throws -> T {
        guard let decoded else {
            throw ThreatModelFileError.unknownValue(field: field, value: raw)
        }
        return decoded
    }
}
