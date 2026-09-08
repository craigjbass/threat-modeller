public protocol BuildThreatModelReportUseCase {
    func execute(_ request: BuildThreatModelReportRequest) -> BuildThreatModelReportResponse
}

public struct BuildThreatModelReportRequest: Equatable, Sendable {
    public init() {}
}

public struct BuildThreatModelReportResponse: Equatable, Sendable {
    public let report: Report

    public init(report: Report) {
        self.report = report
    }
}

/// Turns the model and its assessment into the one tree every report reads.
///
/// It reads the same resolution the sidebar reads, so a report can never
/// disagree with what the user saw on screen.
public struct BuildThreatModelReport: BuildThreatModelReportUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: BuildThreatModelReportRequest) -> BuildThreatModelReportResponse {
        let model = models.current()
        let taxonomy = catalogue.taxonomy()
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        let assessment = AssessThreatModel(models: models, catalogue: catalogue)
            .execute(AssessThreatModelRequest())
        let summary = SummariseRisk(models: models, catalogue: catalogue)
            .execute(SummariseRiskRequest())

        var nameById: [ComponentId: String] = [:]
        for component in model.components {
            nameById[component.id] = component.customName
                ?? lookup.findById(component.technologyId)?.name
                ?? component.technologyId.value
        }

        let zoneByComponent = Dictionary(
            uniqueKeysWithValues: model.components.map { component in
                (
                    component.id,
                    ZoneContainment.zone(holding: component.centre, in: model.zones)
                )
            }
        )

        return BuildThreatModelReportResponse(
            report: Report(
                modelName: model.name,
                catalogueTag: model.catalogueVersion?.tag ?? catalogue.version().tag,
                summary: ReportSummary(
                    totalThreats: summary.totalThreats,
                    byLevel: summary.byLevel.map { ReportCount(label: $0.label, count: $0.count) },
                    byStride: summary.byStride.map { ReportCount(label: $0.label, count: $0.count) },
                    controlsOffered: summary.controlsOffered,
                    controlsRecorded: summary.controlsRecorded,
                    byControlStatus: Self.byStatus(assessment.threats)
                ),
                components: model.components.map { component in
                    ReportComponent(
                        id: component.id.value,
                        name: nameById[component.id] ?? component.technologyId.value,
                        technologyId: component.technologyId.value,
                        categoryId: lookup.findById(component.technologyId)?.category.value ?? "",
                        sensitivityLabel: component.sensitivity.label,
                        zoneName: zoneByComponent[component.id]??.displayName
                    )
                },
                connections: model.connections.map { connection in
                    ReportConnection(
                        sourceName: nameById[connection.source] ?? connection.source.value,
                        targetName: nameById[connection.target] ?? connection.target.value
                    )
                },
                zones: model.zones.map { zone in
                    ReportZone(
                        name: zone.displayName,
                        networkZoneLabel: zone.networkZone.label,
                        networkTypeLabel: zone.networkType.label,
                        componentNames: model.components
                            .filter { zoneByComponent[$0.id] ?? nil == zone }
                            .compactMap { nameById[$0.id] },
                        riskReductionPercent: zone.riskReductionEnabled
                            ? zone.riskReductionPercent
                            : nil
                    )
                },
                threats: assessment.threats.map { assessed in
                    Self.threat(
                        from: assessed,
                        compensating: model.compensatingControls[
                            ThreatKey(
                                threatId: assessed.threatId,
                                sourceId: assessed.source.id
                            )
                        ]?.map {
                            ReportCompensatingControl(
                                label: $0.label,
                                reducesRiskBy: $0.reducesRiskBy,
                                rationale: $0.rationale
                            )
                        } ?? [],
                        // The assessment names STRIDE by id. A report is read
                        // by people, so it names it by label.
                        strideLabels: assessed.stride.compactMap {
                            taxonomy.strideCategory(id: StrideId($0))?.label
                        }
                    )
                }
            )
        )
    }

    /// A control is counted once per distinct key, the way `SummariseRisk`
    /// counts what is offered and what is recorded.
    private static func byStatus(_ threats: [AssessedThreat]) -> [ReportCount] {
        var statusByKey: [String: String] = [:]
        for threat in threats {
            for control in threat.controls {
                statusByKey[control.key] = control.statusLabel
            }
        }

        var counts: [String: Int] = [:]
        for label in statusByKey.values {
            counts[label, default: 0] += 1
        }

        return ["Implemented", "Accepted", "Not applicable", "Not implemented"]
            .compactMap { label in
                counts[label].map { ReportCount(label: label, count: $0) }
            }
    }

    private static func threat(
        from assessed: AssessedThreat,
        compensating: [ReportCompensatingControl],
        strideLabels: [String]
    ) -> ReportThreat {
        ReportThreat(
            threatId: assessed.threatId,
            name: assessed.name,
            description: assessed.description,
            severityLabel: assessed.severityLabel,
            riskScore: assessed.riskScore,
            riskLevel: assessed.riskLevel,
            strideLabels: strideLabels,
            mitreTechniqueIds: assessed.mitreTechniques.map(\.id),
            sourceName: assessed.source.displayName,
            sourceKind: kind(of: assessed.source),
            controls: assessed.controls.map {
                ReportControl(
                    description: $0.description,
                    isImplemented: $0.isImplemented,
                    statusLabel: $0.statusLabel
                )
            },
            pathwayMitigationLabels: assessed.pathwayMitigationLabels,
            compensating: compensating,
            scoreBeforeCompensation: assessed.scoreBeforeCompensation
        )
    }

    private static func kind(of source: AssessedThreatSource) -> String {
        switch source {
        case .component: "Component"
        case .connection: "Connection"
        case .zone: "Zone"
        }
    }
}
