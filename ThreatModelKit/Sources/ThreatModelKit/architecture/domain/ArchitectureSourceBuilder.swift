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
                    assets: component.assets.map { SourceAsset(name: $0.name, data: $0.sensitivity.rawValue) },
                    holds: component.holds,
                    providedBy: component.providedBy,
                    declaredData: component.statesOwnSensitivity
                        ? component.sensitivity.rawValue
                        : nil,
                    tags: component.tags
                )
                if let zoneId = component.zoneId,
                   model.zones.contains(where: { $0.id == zoneId }) {
                    inZone[zoneId, default: []].append(written)
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
                        encrypts: technology.enforcesEncryption,
                        controlDescriptions: technology.controls
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
                        description: zone.description,
                        tags: zone.tags
                    )
                },
                components: loose,
                flows: model.connections.map {
                    SourceFlow(
                        sourceId: $0.source.value,
                        targetId: $0.target.value,
                        kind: $0.kind.rawValue,
                        description: $0.description,
                        tags: $0.tags
                    )
                },
                mitigates: model.mitigatesEdges.map { edge in
                    SourceMitigates(
                        sourceId: edge.source.value,
                        targetId: edge.target.value,
                        threatIds: edge.threatIds.map(\.value),
                        reducesRiskBy: edge.reducesRiskBy,
                        // Straight through: an edge with no status writes no
                        // line, and a file that stated one round trips it.
                        status: edge.status?.rawValue,
                        action: edge.action.map { action in
                            SourceEdgeAction(
                                label: action.label,
                                text: action.text,
                                note: action.note,
                                blockedBy: action.blockedBy,
                                sources: action.sources
                            )
                        }
                    )
                },
                // Straight through: a model with no tolerance writes no
                // line, and a file that stated one round trips it.
                riskTolerance: model.riskTolerance?.rawValue,
                assumptions: model.assumptions.map { assumption in
                    SourceAssumption(
                        label: assumption.label,
                        text: assumption.text,
                        owner: assumption.owner
                    )
                },
                useCases: model.useCases.map {
                    SourceUseCase(label: $0.label, text: $0.text)
                },
                exclusions: model.exclusions.map {
                    SourceExclusion(label: $0.label, text: $0.text, rationale: $0.rationale)
                },
                systemAssets: model.systemAssets.map {
                    SourceSystemAsset(
                        id: $0.id,
                        name: $0.name,
                        classification: $0.classification.rawValue,
                        description: $0.description,
                        owner: $0.owner
                    )
                },
                thirdParties: model.thirdParties.map {
                    SourceThirdParty(
                        id: $0.id,
                        name: $0.name,
                        description: $0.description,
                        kind: $0.kind.rawValue,
                        payingCustomer: $0.payingCustomer,
                        uptime: $0.uptime.rawValue,
                        uptimeNotes: $0.uptimeNotes,
                        owner: $0.owner,
                        link: $0.link
                    )
                },
                diagrams: model.diagrams.map {
                    SourceDiagram(label: $0.label, kind: $0.kind, text: $0.text)
                },
                owner: model.owner.isEmpty ? nil : model.owner,
                // The adversaries this system states. A model that faces
                // nobody writes no line, and a file that stated a list round
                // trips it.
                faces: model.facedActorIds,
                threatActors: model.localActors.map { actor in
                    SourceThreatActor(
                        id: actor.id.value,
                        name: actor.name,
                        description: actor.description,
                        aliases: actor.aliases,
                        capability: actor.capability.id,
                        intent: actor.intent,
                        performs: actor.performs.map(\.value),
                        techniques: actor.techniques,
                        performsCatalogueTier: actor.performsCatalogueTier?.id
                    )
                },
                // What the model states about itself. A model that states
                // none writes none, so a file that never held these lines
                // round trips unchanged.
                description: model.documentFacts.description.isEmpty
                    ? nil
                    : model.documentFacts.description,
                authors: model.documentFacts.authors,
                links: model.documentFacts.links,
                repositories: model.documentFacts.repositories,
                created: model.documentFacts.created.isEmpty ? nil : model.documentFacts.created,
                reviewed: model.documentFacts.reviewed.isEmpty ? nil : model.documentFacts.reviewed,
                version: model.documentFacts.version.isEmpty ? nil : model.documentFacts.version,
                attributes: model.documentFacts.attributes.map {
                    SourceSystemAttribute(name: $0.name, value: $0.value)
                }
            )
        return source
    }
}
