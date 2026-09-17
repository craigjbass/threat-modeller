/// Maps a threat model to the values a picture draws.
///
/// `ViewThreatModel` answers the canvas with these three lists. The layout
/// preview draws the same three lists over the coordinates the search
/// reports. There is one mapping, so the preview and the canvas cannot draw
/// a component differently.
///
/// `docs/superpowers/specs/2026-09-17-layout-preview-design.md` states why
/// the mapping sits here rather than inside the use case.
public enum ViewedModel {
    public static func components(
        of model: ThreatModel,
        catalogue: TechnologyCatalogue
    ) -> [ViewedComponent] {
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        return model.components.map { component in
            // A user has no technology, so the lookup is not asked: a custom
            // technology called `user` is not what a user is.
            let technology = component.isUser ? nil : lookup.findById(component.technologyId)
            let providerId = technology?.provider.value ?? ""
            let categoryId = technology?.category.value ?? ""
            return ViewedComponent(
                id: component.id.value,
                technologyId: component.technologyId.value,
                name: component.customName ?? technology?.name
                    ?? (component.isUser ? component.id.value : component.technologyId.value),
                customName: component.customName,
                providerId: providerId,
                categoryId: categoryId,
                x: component.position.x,
                y: component.position.y,
                sensitivityId: component.sensitivity.rawValue,
                threatsDisabled: component.threatsDisabled,
                isUnknownTechnology: component.isUser == false && technology == nil,
                zoneId: component.zoneId?.value,
                runsAsId: component.runsAs.rawValue,
                shapeId: component.resolvedShape(
                    providerId: providerId,
                    categoryId: categoryId
                ).rawValue,
                shapeOverrideId: component.shape?.rawValue,
                holds: component.holds,
                providedById: component.providedBy,
                tags: component.tags,
                statusId: component.status.rawValue,
                isUser: component.isUser,
                role: component.user?.role ?? "",
                reaches: component.user?.reaches ?? [],
                threatActorId: component.user?.threatActorId,
                version: component.version,
                cves: component.cves,
                assets: component.assets.map {
                    ViewedComponentAsset(
                        name: $0.name,
                        classificationId: $0.sensitivity.rawValue
                    )
                }
            )
        }
    }

    public static func connections(of model: ThreatModel) -> [ViewedConnection] {
        model.connections.map {
            ViewedConnection(
                id: $0.id.value,
                sourceComponentId: $0.source.value,
                targetComponentId: $0.target.value,
                kindId: $0.kind.rawValue,
                description: $0.description,
                carries: $0.carries,
                tags: $0.tags
            )
        }
    }

    public static func zones(of model: ThreatModel) -> [ViewedZone] {
        model.zones.map {
            ViewedZone(
                id: $0.id.value,
                name: $0.displayName,
                customName: $0.name,
                networkZoneId: $0.networkZone.rawValue,
                networkTypeId: $0.networkType.rawValue,
                riskReductionEnabled: $0.riskReductionEnabled,
                riskReductionPercent: $0.riskReductionPercent,
                x: $0.rect.origin.x,
                y: $0.rect.origin.y,
                width: $0.rect.size.width,
                height: $0.rect.size.height,
                boundaryId: $0.boundary.rawValue,
                description: $0.description ?? "",
                tags: $0.tags
            )
        }
    }
}
