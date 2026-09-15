public protocol ImportArchitectureUseCase {
    func execute(_ request: ImportArchitectureRequest) -> ImportArchitectureResponse
}

public struct ImportArchitectureRequest: Equatable, Sendable {
    public let text: String
    /// The `.attacktree` file beside the architecture, or nil when the project
    /// holds none.
    public let attackTreeText: String?

    public init(text: String, attackTreeText: String? = nil) {
        self.text = text
        self.attackTreeText = attackTreeText
    }
}

public enum ImportArchitectureResponse: Equatable, Sendable {
    /// `catalogueTag` is the tag the file states, or nil when it states none.
    /// A reader compares it with the catalogue in use and says what drifted.
    case imported(name: String, warnings: [Diagnostic], catalogueTag: String? = nil)
    case refused(diagnostics: [Diagnostic])
}

/// Draws what an architecture file describes.
///
/// The whole import is one change on the gateway, so one undo takes it back. A
/// technology neither the catalogue nor the file holds is a warning and the
/// component is still placed: the diagram shows what the file says, and the
/// sidebar says what it could not score.
public struct ImportArchitecture: ImportArchitectureUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let sources: ArchitectureSourceGateway
    private let attackTreeSources: AttackTreeSourceGateway
    /// What draws the picture, or nil when nobody looks at it.
    ///
    /// Zone membership comes from the nesting the file states, so a caller
    /// that only scores a model — the compile path — needs no picture and
    /// gives no layout. A component then keeps the origin and a zone gets a
    /// rectangle of nothing.
    private let layout: LayOutModelUseCase?

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        sources: ArchitectureSourceGateway,
        attackTreeSources: AttackTreeSourceGateway = NoAttackTreeSource(),
        layout: LayOutModelUseCase?
    ) {
        self.models = models
        self.catalogue = catalogue
        self.sources = sources
        self.attackTreeSources = attackTreeSources
        self.layout = layout
    }

    public func execute(_ request: ImportArchitectureRequest) -> ImportArchitectureResponse {
        let read = sources.read(request.text)
        guard let source = read.source, read.hasErrors == false else {
            return .refused(diagnostics: read.diagnostics)
        }

        // The trees beside the architecture are part of the system, so
        // importing one reads both. A tree file that does not parse refuses
        // the whole import: half a model states a route nobody can check.
        var attackTrees: [SourceAttackTree] = []
        if let treeText = request.attackTreeText, treeText.isEmpty == false {
            let treeRead = attackTreeSources.read(treeText)
            guard let treeSource = treeRead.source, treeRead.hasErrors == false else {
                return .refused(diagnostics: treeRead.diagnostics)
            }
            attackTrees = treeSource.trees
        }

        // The layout holds no catalogue, and measures the picture it drew, so
        // it needs the shape each component resolves to.
        let shapes = Dictionary(
            uniqueKeysWithValues: source.everyComponent.map { component -> (String, String) in
                let technology = catalogue.findById(TechnologyId(component.technologyId))
                let forced = component.shape.flatMap(DiagramShape.init(rawValue:))
                let resolved = forced ?? DiagramShapeMap.derived(
                    providerId: technology?.provider.value ?? "",
                    categoryId: technology?.category.value ?? ""
                )
                return (component.id, resolved.rawValue)
            }
        )

        let placed = layout?.execute(LayOutModelRequest(source: source, shapes: shapes))
            ?? LayOutModelResponse(components: [], zones: [])
        let positions = Dictionary(
            uniqueKeysWithValues: placed.components.map { ($0.id, Point(x: $0.x, y: $0.y)) }
        )

        let customTechnologies = source.technologies.map { technology in
            CustomTechnology(
                id: TechnologyId(technology.id),
                name: technology.name,
                category: CategoryId(technology.category),
                description: technology.description,
                threatIds: technology.threatIds.map(ThreatId.init),
                enforcesEncryption: technology.encrypts,
                controls: technology.controlDescriptions
            )
        }

        var model = ThreatModel(
            name: source.systemName,
            customTechnologies: customTechnologies,
            catalogueVersion: source.catalogueTag.map {
                CatalogueVersion(repository: catalogue.version().repository, tag: $0)
            }
        )

        // A classification word the project's scheme does not hold is worth
        // saying. The diagram is still drawn: the word states something the
        // team means, and a threat scored against an unknown word ranks at
        // the least the scheme holds rather than refusing the file.
        let scheme = catalogue.classifications()
        var unknownClassifications: [Diagnostic] = []
        var saidAbout: Set<String> = []
        for component in source.everyComponent {
            for word in [component.data] + component.assets.map(\.data)
            where scheme.holds(word) == false && saidAbout.insert(word).inserted {
                unknownClassifications.append(
                    Diagnostic(
                        severity: .warning,
                        line: 1,
                        column: 1,
                        message: "data is \"\(word)\"; this project holds "
                            + scheme.levels.map { "\"\($0.id)\"" }.joined(separator: ", ")
                    )
                )
            }
        }

        // The file already states which zone holds which component, so the
        // membership is read rather than derived from a layout.
        var zoneByComponent: [String: String] = [:]
        for zone in source.zones {
            for component in zone.components { zoneByComponent[component.id] = zone.id }
        }

        for component in source.everyComponent {
            model.components.append(
                Component(
                    id: ComponentId(component.id),
                    technologyId: TechnologyId(component.technologyId),
                    position: positions[component.id] ?? Point(x: 0, y: 0),
                    sensitivity: DataSensitivity(component.data),
                    customName: component.name,
                    threatsDisabled: component.raisesThreats == false,
                    runsAs: PrivilegeLevel(rawValue: component.runsAs) ?? .default,
                    assets: component.assets.map {
                        Asset(name: $0.name, sensitivity: DataSensitivity($0.data))
                    },
                    shape: component.shape.flatMap(DiagramShape.init(rawValue:)),
                    zoneId: zoneByComponent[component.id].map(ZoneId.init)
                )
            )
        }

        for zone in source.zones {
            // With no layout there is no rectangle, and a zone with no
            // rectangle still holds its components: membership is the field,
            // not the geometry. The compile path is the caller that does this.
            let rectangle = placed.zones.first { $0.id == zone.id }
            model.zones.append(
                Zone(
                    id: ZoneId(zone.id),
                    rect: Rect(
                        x: rectangle?.x ?? 0,
                        y: rectangle?.y ?? 0,
                        width: rectangle?.width ?? 0,
                        height: rectangle?.height ?? 0
                    ),
                    name: zone.name,
                    networkZone: NetworkZone(rawValue: zone.kind) ?? .privateZone,
                    networkType: ZoneNetworkType(rawValue: zone.network) ?? .generic,
                    riskReductionEnabled: zone.reducesRisk,
                    riskReductionPercent: zone.reducesRiskBy ?? Zone.defaultRiskReductionPercent,
                    boundary: ZoneBoundary(rawValue: zone.boundary) ?? .default,
                    description: zone.description
                )
            )
        }

        for flow in source.flows {
            model.connections.append(
                Connection(
                    id: ConnectionId(flow.id),
                    source: ComponentId(flow.sourceId),
                    target: ComponentId(flow.targetId),
                    kind: FlowKind(rawValue: flow.kind) ?? .default,
                    description: flow.description
                )
            )
        }

        var statusWarnings: [Diagnostic] = []
        model.mitigatesEdges = source.mitigates.map { edge in
            let status = edge.status.flatMap(MitigationStatus.init(rawValue:))
            if let raw = edge.status, status == nil {
                statusWarnings.append(
                    Diagnostic(
                        severity: .warning,
                        line: 1,
                        column: 1,
                        message: "status is \"\(raw)\"; a mitigates edge is \"adopted\" or \"assumed\""
                    )
                )
            }
            return MitigatesEdge(
                source: ComponentId(edge.sourceId),
                target: ComponentId(edge.targetId),
                threatIds: edge.threatIds.map(ThreatId.init),
                reducesRiskBy: edge.reducesRiskBy,
                status: status,
                action: edge.action.map {
                    EdgeAction(
                        label: $0.label,
                        text: $0.text,
                        note: $0.note,
                        blockedBy: $0.blockedBy,
                        sources: $0.sources
                    )
                }
            )
        }
        model.assumptions = source.assumptions.map {
            SystemAssumption(label: $0.label, text: $0.text, owner: $0.owner)
        }

        var toleranceWarnings: [Diagnostic] = []
        let riskTolerance = source.riskTolerance.flatMap(RiskLevel.init(rawValue:))
        if let raw = source.riskTolerance, riskTolerance == nil {
            toleranceWarnings.append(
                Diagnostic(
                    severity: .warning,
                    line: 1,
                    column: 1,
                    message: "risk_tolerance is \"\(raw)\"; this application holds "
                        + RiskLevel.allCases.map { "\"\($0.rawValue)\"" }.joined(separator: ", ")
                )
            )
        }
        model.riskTolerance = riskTolerance
        model.owner = source.owner ?? ""
        model.requiresEvidenceAbove = source.requiresEvidenceAbove
            .flatMap(RiskLevel.init(rawValue:))
        model.attackTrees = attackTrees

        // Spec section 3.2: a local block is the actor, whole. A parser has
        // already refused a tier word outside the three.
        model.localActors = source.threatActors.map {
            ThreatActor(
                id: ThreatActorId($0.id),
                name: $0.name,
                description: $0.description,
                aliases: $0.aliases,
                capability: $0.capability.flatMap(Likelihood.init(rawValue:)) ?? .targeted,
                intent: $0.intent,
                performs: $0.performs.map(ThreatId.init),
                techniques: $0.techniques,
                performsCatalogueTier: $0.performsCatalogueTier.flatMap(Likelihood.init(rawValue:))
            )
        }
        model.facedActorIds = source.faces

        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        var warnings = read.warnings + statusWarnings + toleranceWarnings
            + unknownClassifications
        for component in source.everyComponent
        where lookup.findById(TechnologyId(component.technologyId)) == nil {
            warnings.append(
                Diagnostic(
                    severity: .warning,
                    line: 1,
                    column: 1,
                    message: "\"\(component.technologyId)\" is neither in this file nor in the "
                        + "catalogue, so \"\(component.id)\" raises no threats"
                )
            )
        }

        // Spec section 3.6: a `faces` entry naming no actor stops the project
        // opening, and a faced actor that performs nothing this model raises
        // is a warning.
        let actors = ThreatActorLookup(model: model, catalogue: catalogue)
        let unknownActorIds = actors.unknownFacedIds()
        if unknownActorIds.isEmpty == false {
            return .refused(
                diagnostics: unknownActorIds.map {
                    Diagnostic(
                        severity: .error,
                        line: 1,
                        column: 1,
                        message: "this project holds no threat actor called \"\($0.value)\""
                    )
                }
            )
        }
        warnings += Self.actorWarnings(model: model, catalogue: catalogue, faced: actors.faced())

        let imported = model
        return models.mutate(label: ChangeLabel.importArchitecture) { current in
            current = imported
            return .imported(
                name: imported.name,
                warnings: warnings,
                catalogueTag: source.catalogueTag
            )
        }
    }

    /// What a faced actor says that this model cannot use.
    ///
    /// Neither stops the project opening: an actor list is a statement about
    /// the world, and a model that does not raise a threat that actor performs
    /// is a normal thing to write.
    static func actorWarnings(
        model: ThreatModel,
        catalogue: TechnologyCatalogue,
        faced: [ThreatActor]
    ) -> [Diagnostic] {
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        let shared = catalogue.connectionThreats() + catalogue.zoneThreats()
        let raised = model.components.flatMap { lookup.threatsFor(technologyId: $0.technologyId) }
            + shared
        let everyThreatId = Set(
            (lookup.all().flatMap { lookup.threatsFor(technologyId: $0.id) } + shared).map(\.id)
        )

        var warnings: [Diagnostic] = []
        for actor in faced {
            for threatId in actor.performs where everyThreatId.contains(threatId) == false {
                warnings.append(
                    Diagnostic(
                        severity: .warning,
                        line: 1,
                        column: 1,
                        message: "the threat actor \"\(actor.id.value)\" performs "
                            + "\"\(threatId.value)\", which no catalogue holds"
                    )
                )
            }
            let performsSomething = raised.contains { threat in
                ActorLikelihood.performers(of: threat, among: [actor]).isEmpty == false
            }
            if performsSomething == false {
                warnings.append(
                    Diagnostic(
                        severity: .warning,
                        line: 1,
                        column: 1,
                        message: "the threat actor \"\(actor.id.value)\" performs no threat "
                            + "this model raises"
                    )
                )
            }
        }
        return warnings
    }


}
