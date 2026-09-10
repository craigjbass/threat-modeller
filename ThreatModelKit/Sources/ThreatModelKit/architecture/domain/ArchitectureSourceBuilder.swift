/// Says what an architecture file holds about a model.
///
/// `ExportArchitecture` writes what is on screen and `InitialiseProject` writes
/// a bundled example, and both must say the same thing about the same model.
public enum ArchitectureSourceBuilder {
    public static func source(from model: ThreatModel) -> ArchitectureSource {


            var inZone: [ZoneId: [SourceComponent]] = [:]
            var loose: [SourceComponent] = []
            for component in model.components {
                let written = SourceComponent(
                    id: component.id.value,
                    technologyId: component.technologyId.value,
                    name: component.customName,
                    data: component.sensitivity.rawValue,
                    raisesThreats: component.threatsDisabled == false,
                    runsAs: component.runsAs.rawValue,
                    assets: component.assets.map { SourceAsset(name: $0.name, data: $0.sensitivity.rawValue) }
                )
                if let zone = ZoneContainment.zone(holding: component.centre, in: model.zones) {
                    inZone[zone.id, default: []].append(written)
                } else {
                    loose.append(written)
                }
            }

            let source = ArchitectureSource(
                systemName: model.name,
                catalogueTag: model.catalogueVersion?.tag,
                technologies: model.customTechnologies.map { technology in
                    SourceTechnology(
                        id: technology.id.value,
                        name: technology.name,
                        category: technology.category.value,
                        description: technology.description,
                        threatIds: technology.threatIds.map(\.value),
                        encrypts: technology.enforcesEncryption
                    )
                },
                zones: model.zones.map { zone in
                    SourceZone(
                        id: zone.id.value,
                        kind: zone.networkZone.rawValue,
                        network: zone.networkType.rawValue,
                        name: zone.name,
                        reducesRisk: zone.riskReductionEnabled,
                        reducesRiskBy: zone.riskReductionPercent,
                        components: inZone[zone.id] ?? [],
                        boundary: zone.boundary.rawValue,
                        description: zone.description
                    )
                },
                components: loose,
                flows: model.connections.map {
                    SourceFlow(
                        sourceId: $0.source.value,
                        targetId: $0.target.value,
                        kind: $0.kind.rawValue,
                        description: $0.description
                    )
                },
                mitigates: model.mitigatesEdges.map { edge in
                    SourceMitigates(
                        sourceId: edge.source.value,
                        targetId: edge.target.value,
                        threatIds: edge.threatIds.map(\.value),
                        reducesRiskBy: edge.reducesRiskBy,
                        // Nil at the default, so an adopted edge writes no
                        // line and a file that never stated one round trips
                        // unchanged.
                        status: edge.status == .assumed ? edge.status.rawValue : nil
                    )
                },
                // Nil at the default, so a file that never states a tolerance
                // still writes back exactly as it read.
                riskTolerance: model.riskTolerance == .low ? nil : model.riskTolerance.rawValue,
                assumptions: model.assumptions.map { assumption in
                    SourceAssumption(
                        label: assumption.label,
                        text: assumption.text,
                        owner: assumption.owner
                    )
                }
            )
        return source
    }
}
