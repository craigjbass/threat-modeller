import Foundation

public protocol ExportModelAsOtmUseCase {
    func execute(_ request: ExportModelAsOtmRequest) -> ExportModelAsOtmResponse
}

public struct ExportModelAsOtmRequest: Equatable, Sendable {
    public init() {}
}

public struct ExportModelAsOtmResponse: Equatable, Sendable {
    public let json: String
    public let fileName: String

    public init(json: String, fileName: String) {
        self.json = json
        self.fileName = fileName
    }
}

/// Writes the model as an Open Threat Model file.
///
/// OTM is what other threat-modelling tools read. It states a project, trust
/// zones, components, dataflows, threats and mitigations, and it states no
/// score of its own: a threat carries `risk` with a likelihood and an impact,
/// so this writes the assessment's numbers there. The mapping from this model
/// to that schema is written in `docs/OTM-MAPPING.md`.
///
/// Keys are written in alphabetical order, so two exports of one model are
/// the same bytes.
public struct ExportModelAsOtm: ExportModelAsOtmUseCase {
    /// The version of the Open Threat Model schema this writes.
    public static let otmVersion = "0.2.0"

    private let reports: BuildThreatModelReportUseCase

    public init(reports: BuildThreatModelReportUseCase) {
        self.reports = reports
    }

    public func execute(_ request: ExportModelAsOtmRequest) -> ExportModelAsOtmResponse {
        let report = reports.execute(BuildThreatModelReportRequest()).report
        let document = OtmDocument(report)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let data = (try? encoder.encode(document)) ?? Data()

        return ExportModelAsOtmResponse(
            json: String(decoding: data, as: UTF8.self) + "\n",
            fileName: "\(FileNaming.stem(from: report.modelName)).otm.json"
        )
    }
}

struct OtmDocument: Codable {
    let otmVersion: String
    let project: OtmProject
    let representations: [OtmRepresentation]
    let trustZones: [OtmTrustZone]
    let components: [OtmComponent]
    let dataflows: [OtmDataflow]
    let threats: [OtmThreat]
    let mitigations: [OtmMitigation]

    init(_ report: Report) {
        otmVersion = ExportModelAsOtm.otmVersion
        project = OtmProject(
            id: FileNaming.stem(from: report.modelName),
            name: report.modelName,
            owner: report.documentControl.owner,
            description: report.documentControl.description
        )
        // One representation: the diagram this application draws. OTM asks
        // for a representation before a component may state where it sits,
        // and this model states no coordinates in a report.
        representations = [
            OtmRepresentation(
                id: "\(FileNaming.stem(from: report.modelName))-diagram",
                name: "\(report.modelName) data-flow diagram",
                type: "diagram"
            )
        ]
        trustZones = report.zones.map {
            OtmTrustZone(
                id: OtmDocument.identifier($0.name),
                name: $0.name,
                description: "\($0.networkZoneLabel), \($0.networkTypeLabel)",
                risk: OtmTrustZoneRisk(trustRating: $0.riskReductionPercent ?? 0)
            )
        }
        var zoneByComponent: [String: String] = [:]
        for zone in report.zones {
            for id in zone.componentIds { zoneByComponent[id] = OtmDocument.identifier(zone.name) }
        }
        components = report.components.map {
            OtmComponent(
                id: $0.id,
                name: $0.name,
                type: $0.categoryId.isEmpty ? "generic-component" : $0.categoryId,
                parent: OtmParent(trustZone: zoneByComponent[$0.id]),
                tags: [$0.technologyId, $0.sensitivityLabel, $0.privilegeLabel, $0.statusLabel],
                modelTags: $0.tags
            )
        }
        var nameToId: [String: String] = [:]
        for component in report.components { nameToId[component.name] = component.id }
        dataflows = report.connections.map { flow in
            let source = nameToId[flow.sourceName] ?? flow.sourceName
            let target = nameToId[flow.targetName] ?? flow.targetName
            return OtmDataflow(
                id: "\(source)->\(target)",
                name: "\(flow.sourceName) to \(flow.targetName)",
                description: flow.description,
                source: source,
                destination: target,
                tags: [flow.kindLabel],
                modelTags: flow.tags
            )
        }
        // OTM keys a threat once and lists what it sits on, and this model
        // raises one threat on many elements. Each pair is one OTM threat, so
        // no score is lost, and the id says which pair it is.
        threats = report.threats.map { threat in
            OtmThreat(
                id: "\(threat.threatId)@\(threat.sourceId)",
                name: threat.name,
                description: threat.description,
                categories: threat.strideLabels,
                cwes: [],
                risk: OtmThreatRisk(
                    likelihood: threat.likelihoodLabel,
                    impact: threat.impactLabels.joined(separator: ", "),
                    score: threat.riskScore,
                    inherentScore: threat.inherentScore,
                    level: threat.riskLevel
                ),
                attributes: OtmThreatAttributes(
                    severity: threat.severityLabel,
                    isOpen: threat.isOpen,
                    raisedBy: threat.sourceKind,
                    element: threat.sourceName,
                    assetsAtRisk: threat.assetsAtRisk,
                    mitreTechniqueIds: threat.mitreTechniqueIds
                )
            )
        }
        mitigations = report.threats.flatMap { threat in
            threat.controls.map { control in
                OtmMitigation(
                    id: OtmDocument.identifier("\(threat.threatId)-\(control.description)"),
                    name: control.description,
                    description: control.evidence ?? "",
                    riskReduction: control.isImplemented ? 100 : 0,
                    attributes: OtmMitigationAttributes(
                        status: control.statusLabel,
                        threat: "\(threat.threatId)@\(threat.sourceId)"
                    )
                )
            }
        }
    }

    /// A label a person wrote, as an identifier another tool accepts: lower
    /// case, and a dash wherever the label holds anything else.
    static func identifier(_ label: String) -> String {
        var built = ""
        var lastWasDash = false
        for character in label.lowercased() {
            if character.isLetter || character.isNumber {
                built.append(character)
                lastWasDash = false
            } else if lastWasDash == false {
                built.append("-")
                lastWasDash = true
            }
        }
        while built.hasPrefix("-") { built.removeFirst() }
        while built.hasSuffix("-") { built.removeLast() }
        return built.isEmpty ? "unnamed" : built
    }
}

struct OtmProject: Codable {
    let id: String
    let name: String
    let owner: String?
    let description: String?
}

struct OtmRepresentation: Codable {
    let id: String
    let name: String
    let type: String
}

struct OtmTrustZone: Codable {
    let id: String
    let name: String
    let description: String
    let risk: OtmTrustZoneRisk
}

struct OtmTrustZoneRisk: Codable {
    let trustRating: Int
}

struct OtmComponent: Codable {
    let id: String
    let name: String
    let type: String
    let parent: OtmParent
    /// The tags this export synthesises from technology, sensitivity,
    /// privilege and status.
    let tags: [String]
    /// The tags the model states for itself, separate from the synthesised
    /// ones above.
    let modelTags: [String]
}

struct OtmParent: Codable {
    let trustZone: String?
}

struct OtmDataflow: Codable {
    let id: String
    let name: String
    let description: String?
    let source: String
    let destination: String
    /// The tag this export synthesises from the flow's kind.
    let tags: [String]
    /// The tags the model states for itself, separate from the synthesised
    /// one above.
    let modelTags: [String]
}

struct OtmThreat: Codable {
    let id: String
    let name: String
    let description: String
    let categories: [String]
    let cwes: [String]
    let risk: OtmThreatRisk
    let attributes: OtmThreatAttributes
}

struct OtmThreatRisk: Codable {
    let likelihood: String
    let impact: String
    let score: Int
    let inherentScore: Int
    let level: String
}

struct OtmThreatAttributes: Codable {
    let severity: String
    let isOpen: Bool
    let raisedBy: String
    let element: String
    let assetsAtRisk: [String]
    let mitreTechniqueIds: [String]
}

struct OtmMitigation: Codable {
    let id: String
    let name: String
    let description: String
    let riskReduction: Int
    let attributes: OtmMitigationAttributes
}

struct OtmMitigationAttributes: Codable {
    let status: String
    let threat: String
}
