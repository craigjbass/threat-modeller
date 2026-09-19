public protocol ImportArchitectureUseCase {
    func execute(_ request: ImportArchitectureRequest) -> ImportArchitectureResponse
}

public struct ImportArchitectureRequest: Equatable, Sendable {
    public let text: String
    /// The `.attacktree` file beside the architecture, or nil when the project
    /// holds none.
    public let attackTreeText: String?
    /// Every architecture file of one system, when the system is split across
    /// files. Empty means the one `text` above, which is a flat system.
    public let parts: [SourcePart]
    /// The name the directory gives a split system, for the message that
    /// names a header whose label differs.
    public let directoryName: String?
    /// Every `.attacktree` file of a split system. Empty means the one
    /// `attackTreeText` above.
    public let attackTreeTexts: [String]

    public init(
        text: String,
        attackTreeText: String? = nil,
        parts: [SourcePart] = [],
        directoryName: String? = nil,
        attackTreeTexts: [String] = []
    ) {
        self.text = text
        self.attackTreeText = attackTreeText
        self.parts = parts
        self.directoryName = directoryName
        self.attackTreeTexts = attackTreeTexts
    }

    /// Every architecture file this request states, as parts.
    public var everyPart: [SourcePart] {
        parts.isEmpty ? [SourcePart(file: "", text: text)] : parts
    }

    /// Every attack tree file this request states.
    public var everyAttackTreeText: [String] {
        attackTreeTexts.isEmpty ? [attackTreeText].compactMap { $0 } : attackTreeTexts
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
    /// Where the subject the search draws is stated, or nil when nobody
    /// watches the search. Only the window passes one.
    private let progress: LayoutProgress?

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        sources: ArchitectureSourceGateway,
        attackTreeSources: AttackTreeSourceGateway = NoAttackTreeSource(),
        layout: LayOutModelUseCase?,
        progress: LayoutProgress? = nil
    ) {
        self.models = models
        self.catalogue = catalogue
        self.sources = sources
        self.attackTreeSources = attackTreeSources
        self.layout = layout
        self.progress = progress
    }

    public func execute(_ request: ImportArchitectureRequest) -> ImportArchitectureResponse {
        // A split system is several files, merged into one source with one
        // namespace. A flat system is the one-file case and reads exactly
        // what it read before.
        let read = sources.read(request.everyPart, named: request.directoryName)
        guard let source = read.source, read.hasErrors == false else {
            return .refused(diagnostics: read.diagnostics)
        }

        // The trees beside the architecture are part of the system, so
        // importing one reads both. A tree file that does not parse refuses
        // the whole import: half a model states a route nobody can check.
        var attackTrees: [SourceAttackTree] = []
        var treeCatalogueWarnings: [Diagnostic] = []
        for treeText in request.everyAttackTreeText where treeText.isEmpty == false {
            let treeRead = attackTreeSources.read(treeText)
            guard let treeSource = treeRead.source, treeRead.hasErrors == false else {
                return .refused(diagnostics: treeRead.diagnostics)
            }
            attackTrees += treeSource.trees

            // A tree file states the catalogue tag it was written against,
            // the way a library file does. A tree file pinned to another tag
            // may name a step or a goal this catalogue no longer holds.
            if let stated = treeSource.catalogueTag, stated != catalogue.version().tag {
                treeCatalogueWarnings.append(
                    Diagnostic(
                        severity: .warning,
                        line: 1,
                        column: 1,
                        message: "the attack tree file was written against catalogue "
                            + "\(stated), and the catalogue in use is \(catalogue.version().tag)"
                    )
                )
            }
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
            documentFacts: DocumentFacts(
                description: source.description ?? "",
                authors: source.authors,
                links: source.links,
                repositories: source.repositories,
                created: source.created ?? "",
                reviewed: source.reviewed ?? "",
                version: source.version ?? "",
                attributes: source.attributes.map { (name: $0.name, value: $0.value) }
            ),

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

        // A component that states a classification below one it holds says
        // two things at once. The stated word stands, and the warning names
        // the asset that disagrees with it.
        var lowerThanHeld: [Diagnostic] = []
        let classificationByAsset = Dictionary(
            source.systemAssets.map { ($0.id, $0.classification) },
            uniquingKeysWith: { first, _ in first }
        )
        for component in source.everyComponent {
            guard let stated = component.declaredData else { continue }
            let statedRank = DataSensitivity(stated).rank(in: scheme)
            for held in component.holds {
                guard let word = classificationByAsset[held] else { continue }
                guard DataSensitivity(word).rank(in: scheme) > statedRank else { continue }
                lowerThanHeld.append(
                    Diagnostic(
                        severity: .warning,
                        line: 1,
                        column: 1,
                        message: "the component \"\(component.id)\" states data \"\(stated)\" "
                            + "and holds \"\(held)\", which is \"\(word)\""
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

        model.systemAssets = source.systemAssets.map {
            SystemAsset(
                id: $0.id,
                name: $0.name,
                classification: DataSensitivity($0.classification),
                description: $0.description,
                owner: $0.owner
            )
        }
        model.thirdParties = source.thirdParties.map {
            ThirdParty(
                id: $0.id,
                name: $0.name,
                description: $0.description,
                kind: ThirdPartyKind(rawValue: $0.kind) ?? .saas,
                payingCustomer: $0.payingCustomer,
                uptime: UptimeDependency(rawValue: $0.uptime) ?? .none,
                uptimeNotes: $0.uptimeNotes,
                owner: $0.owner,
                link: $0.link
            )
        }
        model.diagrams = source.diagrams.map {
            SystemDiagram(label: $0.label, kind: $0.kind, text: $0.text)
        }
        let classificationById = Dictionary(
            model.systemAssets.map { ($0.id, $0.classification) },
            uniquingKeysWith: { first, _ in first }
        )

        for component in source.everyComponent {
            // A component that states what it holds and states no `data` of
            // its own takes the highest classification it holds. A component
            // that states both keeps its own word, and the warning below says
            // when that word is the lower of the two.
            let held = component.holds.compactMap { classificationById[$0] }
            let highestHeld = SensitivityLadder.highest(of: held)
            let sensitivity = component.declaredData == nil
                ? (highestHeld ?? DataSensitivity(component.data))
                : DataSensitivity(component.data)

            model.components.append(
                Component(
                    id: ComponentId(component.id),
                    technologyId: TechnologyId(component.technologyId),
                    // The search runs below, once the model it draws exists.
                    position: Point(x: 0, y: 0),
                    sensitivity: sensitivity,
                    customName: component.name,
                    threatsDisabled: component.raisesThreats == false,
                    runsAs: PrivilegeLevel(rawValue: component.runsAs) ?? .default,
                    assets: component.assets.map {
                        Asset(name: $0.name, sensitivity: DataSensitivity($0.data))
                    },
                    holds: component.holds,
                    providedBy: component.providedBy,
                    statesOwnSensitivity: component.declaredData != nil,
                    shape: component.shape.flatMap(DiagramShape.init(rawValue:)),
                    zoneId: zoneByComponent[component.id].map(ZoneId.init),
                    tags: component.tags,
                    status: ComponentStatus(rawValue: component.status) ?? .default,
                    version: component.version,
                    cves: component.cves,
                    source: component.source
                )
            )
        }

        // A user is a component with no technology: the user's name is the
        // custom name, the access is the privilege, and the user facts carry
        // the rest. The user block design states it.
        for user in source.users {
            model.components.append(
                Component(
                    id: ComponentId(user.id),
                    technologyId: Component.userTechnologyId,
                    position: Point(x: 0, y: 0),
                    sensitivity: .internalData,
                    customName: user.name,
                    runsAs: PrivilegeLevel(rawValue: user.access) ?? .default,
                    statesOwnSensitivity: false,
                    user: UserFacts(
                        role: user.role,
                        uses: user.uses,
                        reaches: user.reaches,
                        threatActorId: user.threatActorId,
                        isAdversary: user.isAdversary,
                        clearanceId: user.clearanceId
                    )
                )
            )
        }

        for zone in source.zones {
            // With no layout there is no rectangle, and a zone with no
            // rectangle still holds its components: membership is the field,
            // not the geometry. The compile path is the caller that does this.
            model.zones.append(
                Zone(
                    id: ZoneId(zone.id),
                    rect: Rect(x: 0, y: 0, width: 0, height: 0),
                    name: zone.name,
                    networkZone: NetworkZone(rawValue: zone.kind) ?? .privateZone,
                    networkType: ZoneNetworkType(rawValue: zone.network) ?? .generic,
                    riskReductionEnabled: zone.reducesRisk,
                    riskReductionPercent: zone.reducesRiskBy ?? Zone.defaultRiskReductionPercent,
                    boundary: ZoneBoundary(rawValue: zone.boundary) ?? .default,
                    description: zone.description,
                    source: zone.source,
                    tags: zone.tags
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
                    description: flow.description,
                    carries: flow.carries,
                    tags: flow.tags
                )
            )
        }

        // The search runs here, and not before the model is built, because
        // a preview draws the model: the names, the shapes and the flows. A
        // subject is stated first, so a listener that hears a report has a
        // picture to draw it over.
        // `docs/superpowers/specs/2026-09-17-layout-preview-design.md`.
        progress?.describe(LayoutSubject.of(model, catalogue: catalogue))

        // The layout places a user beside the components, as an actor.
        let placed = layout?.execute(
            LayOutModelRequest(
                source: source,
                shapes: shapes.merging(
                    source.users.map { ($0.id, DiagramShape.actor.rawValue) },
                    uniquingKeysWith: { first, _ in first }
                )
            )
        ) ?? LayOutModelResponse(components: [], zones: [])
        Self.place(&model, at: placed)

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
        model.useCases = source.useCases.map {
            SystemUseCase(label: $0.label, text: $0.text)
        }
        model.exclusions = source.exclusions.map {
            SystemExclusion(label: $0.label, text: $0.text, rationale: $0.rationale)
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
        model.clearances = source.clearances.map {
            Clearance(
                id: $0.id,
                name: $0.name,
                description: $0.description,
                reducesInsiderRiskBy: $0.reducesInsiderRiskBy,
                rationale: $0.rationale,
                sources: $0.sources
            )
        }

        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        var warnings = read.warnings + statusWarnings + toleranceWarnings
            + unknownClassifications + lowerThanHeld + treeCatalogueWarnings
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
                        // An ATT&CK group nothing holds is a machine that has
                        // not synchronised, so the message names the step
                        // rather than only the id.
                        message: $0.value.hasPrefix(MitreActorSource.prefix)
                            ? "this project holds no threat actor called \"\($0.value)\"; "
                                + "run threatmodeller attack sync to bring the ATT&CK groups "
                                + "onto this machine"
                            : "this project holds no threat actor called \"\($0.value)\""
                    )
                }
            )
        }
        // A user that names an actor nothing declares stops the project
        // opening the way a `faces` entry does: the assessment would face an
        // actor it cannot read.
        let unknownUserActors = actors.unknownUserActors()
        if unknownUserActors.isEmpty == false {
            return .refused(
                diagnostics: unknownUserActors.map {
                    Diagnostic(
                        severity: .error,
                        line: 1,
                        column: 1,
                        message: "the user \"\($0.userId.value)\" names the threat actor "
                            + "\"\($0.actorId.value)\", which no threat_actor block declares"
                    )
                }
            )
        }
        // A user that names a clearance nothing declares stops the project
        // opening the way a user that names an unknown actor does.
        let declaredClearances = Set(model.clearances.map(\.id))
        let unknownClearances = model.components.compactMap { component -> Diagnostic? in
            guard let named = component.clearanceId,
                  declaredClearances.contains(named) == false else { return nil }
            return Diagnostic(
                severity: .error,
                line: 1,
                column: 1,
                message: "the user \"\(component.id.value)\" names the clearance "
                    + "\"\(named)\", which no clearance block declares"
            )
        }
        if unknownClearances.isEmpty == false {
            return .refused(diagnostics: unknownClearances)
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

    /// Moves every element the search placed. An element the search did not
    /// name keeps the coordinates it has, which is the origin for a component
    /// and a rectangle of nothing for a zone.
    static func place(_ model: inout ThreatModel, at placed: LayOutModelResponse) {
        let positions = Dictionary(
            uniqueKeysWithValues: placed.components.map { ($0.id, Point(x: $0.x, y: $0.y)) }
        )
        for index in model.components.indices {
            guard let point = positions[model.components[index].id.value] else { continue }
            model.components[index].position = point
        }

        let rects = Dictionary(
            uniqueKeysWithValues: placed.zones.map {
                ($0.id, Rect(x: $0.x, y: $0.y, width: $0.width, height: $0.height))
            }
        )
        for index in model.zones.indices {
            guard let rect = rects[model.zones[index].id.value] else { continue }
            model.zones[index].rect = rect
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
