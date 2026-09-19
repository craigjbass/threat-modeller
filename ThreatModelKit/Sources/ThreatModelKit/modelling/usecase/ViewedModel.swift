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
                uses: component.user?.clientIds ?? [],
                usePaths: (component.user?.uses ?? []).map {
                    ViewedUse(clientId: $0.clientId, reaches: $0.reaches)
                },
                reaches: component.user?.reaches ?? [],
                threatActorId: component.user?.threatActorId,
                isAdversary: component.isAdversary,
                clearanceId: component.clearanceId,
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

    /// The model's flows, then one use link per user and client pair, in
    /// model order. The picture draws the path a person takes: the user,
    /// the client, then the client's own flows onward.
    public static func connections(of model: ThreatModel) -> [ViewedConnection] {
        let flows = model.connections.map {
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
        let uses = model.components.flatMap { user in
            (user.user?.uses ?? []).map { use in
                ViewedConnection(
                    id: ViewedConnection.useLinkId(user: user.id.value, client: use.clientId),
                    sourceComponentId: user.id.value,
                    targetComponentId: use.clientId,
                    kindId: FlowKind.human.rawValue,
                    isUse: true
                )
            }
        }
        let reaches = model.components.flatMap { user in
            (user.user?.uses ?? []).flatMap { use in
                use.reaches.map { reached in
                    ViewedConnection(
                        id: UserUse.reachId(
                            user: user.id.value,
                            client: use.clientId,
                            reached: reached
                        ),
                        sourceComponentId: use.clientId,
                        targetComponentId: reached,
                        kindId: FlowKind.human.rawValue,
                        isUse: true,
                        isReach: true
                    )
                }
            }
        }
        return flows + uses + reaches
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
