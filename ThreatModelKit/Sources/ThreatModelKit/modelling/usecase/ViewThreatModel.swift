public protocol ViewThreatModelUseCase {
    func execute(_ request: ViewThreatModelRequest) -> ViewThreatModelResponse
}

public struct ViewThreatModelRequest: Equatable, Sendable {
    public init() {}
}

/// One `asset` block a component states on itself: a thing of value the
/// component holds, with the classification of that thing.
public struct ViewedComponentAsset: Equatable, Sendable {
    public let name: String
    /// A classification id, taking the words a component's `data` takes.
    public let classificationId: String

    public init(name: String, classificationId: String) {
        self.name = name
        self.classificationId = classificationId
    }
}

public struct ViewedComponent: Equatable, Sendable {
    public let id: String
    public let technologyId: String
    /// The user's own name when they set one, else the technology's name, else
    /// the technology id when the catalogue no longer holds that technology.
    public let name: String
    /// Only the user's own name, or nil. The node panel needs to tell an
    /// empty field from a field showing the technology's name.
    public let customName: String?
    /// Empty when the catalogue no longer holds the technology.
    public let providerId: String
    /// Empty when the catalogue no longer holds the technology.
    public let categoryId: String
    public let x: Double
    public let y: Double
    public let sensitivityId: String
    public let threatsDisabled: Bool
    /// True when the catalogue has no entry for `technologyId`. A model saved
    /// against an older catalogue can carry one. The canvas still draws it.
    public let isUnknownTechnology: Bool
    /// The zone whose rectangle holds this component's centre, or nil.
    /// Derived from the geometry every time; nothing stores it.
    public let zoneId: String?
    /// The privilege the component runs at: user, admin, root, system or
    /// kernel.
    public let runsAsId: String
    /// The shape to draw: actor, process or store. Already resolved.
    public let shapeId: String
    /// Only the shape the user forced, or nil. The panel needs to tell Auto
    /// from a forced value the derivation would have given anyway.
    public let shapeOverrideId: String?
    /// The system asset ids this component holds, in model order.
    public let holds: [String]
    /// The third party that provides this component, or nil when none does.
    public let providedById: String?
    /// The words a team files this component under, in model order. The canvas
    /// tag filter reads them; no score does.
    public let tags: [String]
    /// Whether the component runs in Production today or is a planned change:
    /// `live` or `proposed`. The canvas draws a proposed component broken.
    public let statusId: String
    /// True for a user: a human with no technology, drawn with the actor
    /// shape. The user block design states it.
    public let isUser: Bool
    /// What the user does with the system. Empty for a technology component
    /// and for a user that states no role.
    public let role: String
    /// The component ids the user reaches, in model order. Empty for a
    /// technology component.
    public let reaches: [String]
    /// The threat actor this user is, or nil.
    public let threatActorId: String?
    /// The version of the software this component runs. Empty when the file
    /// states none.
    public let version: String
    /// The CVE ids the component carries, in model order.
    public let cves: [String]
    /// The `asset` blocks the component states on itself, in model order.
    /// These are the component's own assets, not the system assets it holds.
    public let assets: [ViewedComponentAsset]

    public init(
        id: String,
        technologyId: String,
        name: String,
        customName: String?,
        providerId: String,
        categoryId: String,
        x: Double,
        y: Double,
        sensitivityId: String,
        threatsDisabled: Bool,
        isUnknownTechnology: Bool,
        zoneId: String?,
        runsAsId: String = PrivilegeLevel.default.rawValue,
        shapeId: String = DiagramShape.process.rawValue,
        shapeOverrideId: String? = nil,
        holds: [String] = [],
        providedById: String? = nil,
        tags: [String] = [],
        statusId: String = ComponentStatus.default.rawValue,
        isUser: Bool = false,
        role: String = "",
        reaches: [String] = [],
        threatActorId: String? = nil,
        version: String = "",
        cves: [String] = [],
        assets: [ViewedComponentAsset] = []
    ) {
        self.assets = assets
        self.version = version
        self.cves = cves
        self.isUser = isUser
        self.role = role
        self.reaches = reaches
        self.threatActorId = threatActorId
        self.statusId = statusId
        self.tags = tags
        self.holds = holds
        self.providedById = providedById
        self.id = id
        self.technologyId = technologyId
        self.name = name
        self.customName = customName
        self.providerId = providerId
        self.categoryId = categoryId
        self.x = x
        self.y = y
        self.sensitivityId = sensitivityId
        self.threatsDisabled = threatsDisabled
        self.isUnknownTechnology = isUnknownTechnology
        self.zoneId = zoneId
        self.runsAsId = runsAsId
        self.shapeId = shapeId
        self.shapeOverrideId = shapeOverrideId
    }

    /// The same component at another point.
    ///
    /// A narrowed canvas lays the drawn set out on its own and holds the
    /// result in view state, so it needs one field changed and the other
    /// twenty-five carried over. Nothing here writes the model.
    public func moved(x: Double, y: Double) -> ViewedComponent {
        ViewedComponent(
            id: id,
            technologyId: technologyId,
            name: name,
            customName: customName,
            providerId: providerId,
            categoryId: categoryId,
            x: x,
            y: y,
            sensitivityId: sensitivityId,
            threatsDisabled: threatsDisabled,
            isUnknownTechnology: isUnknownTechnology,
            zoneId: zoneId,
            runsAsId: runsAsId,
            shapeId: shapeId,
            shapeOverrideId: shapeOverrideId,
            holds: holds,
            providedById: providedById,
            tags: tags,
            statusId: statusId,
            isUser: isUser,
            role: role,
            reaches: reaches,
            threatActorId: threatActorId,
            version: version,
            cves: cves,
            assets: assets
        )
    }
}

public struct ViewedConnection: Equatable, Sendable {
    public let id: String
    public let sourceComponentId: String
    public let targetComponentId: String
    /// A flow kind: network, ipc, file, syscall or human.
    public let kindId: String
    /// Why the flow is there, or nil when the user has not said.
    public let description: String?
    /// The system asset ids this connection carries, in model order.
    public let carries: [String]
    /// The words a team files this flow under, in model order. The canvas tag
    /// filter reads them; no score does.
    public let tags: [String]

    public init(
        id: String,
        sourceComponentId: String,
        targetComponentId: String,
        kindId: String = FlowKind.default.rawValue,
        description: String? = nil,
        carries: [String] = [],
        tags: [String] = []
    ) {
        self.tags = tags
        self.carries = carries
        self.id = id
        self.sourceComponentId = sourceComponentId
        self.targetComponentId = targetComponentId
        self.kindId = kindId
        self.description = description
    }
}

public struct ViewedZone: Equatable, Sendable {
    public let id: String
    /// What the canvas shows in the zone header: the user's own name, else the
    /// network type, else the zone kind.
    public let name: String
    /// The user's own name, or nil when they have not set one. The panel edits
    /// this, not `name`.
    public let customName: String?
    public let networkZoneId: String
    public let networkTypeId: String
    public let riskReductionEnabled: Bool
    public let riskReductionPercent: Int
    public let x: Double
    public let y: Double
    public let width: Double
    public let height: Double
    /// What the zone is a boundary of: network or privilege.
    public let boundaryId: String
    /// What a team states this zone is, in their own words. Empty when the
    /// file states none. The zone panel edits this.
    public let description: String
    /// The words a team files this zone under, in model order. The canvas tag
    /// filter reads them; no score does.
    public let tags: [String]

    public init(
        id: String,
        name: String,
        customName: String?,
        networkZoneId: String,
        networkTypeId: String,
        riskReductionEnabled: Bool,
        riskReductionPercent: Int,
        x: Double,
        y: Double,
        width: Double,
        height: Double,
        boundaryId: String = ZoneBoundary.default.rawValue,
        description: String = "",
        tags: [String] = []
    ) {
        self.tags = tags
        self.id = id
        self.name = name
        self.customName = customName
        self.networkZoneId = networkZoneId
        self.networkTypeId = networkTypeId
        self.riskReductionEnabled = riskReductionEnabled
        self.riskReductionPercent = riskReductionPercent
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.boundaryId = boundaryId
        self.description = description
    }

    /// The same zone at another rectangle. A narrowed canvas holds the
    /// rectangle the subset layout gave the zone, and writes no model.
    public func moved(x: Double, y: Double, width: Double, height: Double) -> ViewedZone {
        ViewedZone(
            id: id,
            name: name,
            customName: customName,
            networkZoneId: networkZoneId,
            networkTypeId: networkTypeId,
            riskReductionEnabled: riskReductionEnabled,
            riskReductionPercent: riskReductionPercent,
            x: x,
            y: y,
            width: width,
            height: height,
            boundaryId: boundaryId,
            description: description,
            tags: tags
        )
    }
}

/// What a system takes on trust, as the interface reads it.
public struct ViewedAssumption: Equatable, Sendable {
    public let label: String
    public let text: String
    public let owner: String?

    public init(label: String, text: String, owner: String?) {
        self.label = label
        self.text = text
        self.owner = owner
    }
}

/// One named thing of value the system holds, as the interface reads it.
public struct ViewedSystemAsset: Equatable, Sendable {
    public let id: String
    public let name: String
    public let classificationId: String
    public let description: String
    public let owner: String?

    public init(
        id: String,
        name: String,
        classificationId: String,
        description: String = "",
        owner: String? = nil
    ) {
        self.id = id
        self.name = name
        self.classificationId = classificationId
        self.description = description
        self.owner = owner
    }
}

/// One party outside this team the system depends on, as the interface reads
/// it.
public struct ViewedThirdParty: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    /// A kind id: `saas`, `open_source`, `infrastructure` or `contractor`.
    public let kindId: String
    /// The kind in words, so a panel draws it without a second lookup.
    public let kindLabel: String
    public let payingCustomer: Bool
    /// An uptime id: `none`, `degraded`, `hard` or `operational`.
    public let uptimeId: String
    /// The uptime in words.
    public let uptimeLabel: String
    public let uptimeNotes: String
    public let owner: String?
    public let link: String?

    public init(
        id: String,
        name: String,
        description: String = "",
        kindId: String,
        kindLabel: String,
        payingCustomer: Bool = false,
        uptimeId: String,
        uptimeLabel: String,
        uptimeNotes: String = "",
        owner: String? = nil,
        link: String? = nil
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.kindId = kindId
        self.kindLabel = kindLabel
        self.payingCustomer = payingCustomer
        self.uptimeId = uptimeId
        self.uptimeLabel = uptimeLabel
        self.uptimeNotes = uptimeNotes
        self.owner = owner
        self.link = link
    }
}

/// One picture a team keeps beside the diagram the canvas draws, as the
/// interface reads it. Mermaid is the one kind this application draws.
public struct ViewedSystemDiagram: Equatable, Sendable {
    public let label: String
    public let text: String

    public init(label: String, text: String) {
        self.label = label
        self.text = text
    }
}

/// One thing the team states that the language does not name.
public struct ViewedSystemAttribute: Equatable, Sendable {
    public let name: String
    public let value: String

    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }
}

/// What the document states about itself, as the interface reads it. Every
/// text is empty and every list is empty when the file states none.
public struct ViewedSystemFacts: Equatable, Sendable {
    public let owner: String
    public let description: String
    public let authors: [String]
    public let version: String
    /// `YYYY-MM-DD`, or empty when the file states no date.
    public let created: String
    public let reviewed: String
    public let links: [String]
    public let repositories: [String]
    /// The free-form attribute blocks, in file order.
    public let attributes: [ViewedSystemAttribute]

    public init(
        owner: String = "",
        description: String = "",
        authors: [String] = [],
        version: String = "",
        created: String = "",
        reviewed: String = "",
        links: [String] = [],
        repositories: [String] = [],
        attributes: [ViewedSystemAttribute] = []
    ) {
        self.owner = owner
        self.description = description
        self.authors = authors
        self.version = version
        self.created = created
        self.reviewed = reviewed
        self.links = links
        self.repositories = repositories
        self.attributes = attributes
    }
}

/// One thing a person does with the system, as the interface reads it.
public struct ViewedUseCase: Equatable, Sendable {
    public let label: String
    public let text: String

    public init(label: String, text: String) {
        self.label = label
        self.text = text
    }
}

/// One thing this model does not cover, and why, as the interface reads it.
public struct ViewedExclusion: Equatable, Sendable {
    public let label: String
    public let text: String
    public let rationale: String

    public init(label: String, text: String, rationale: String) {
        self.label = label
        self.text = text
        self.rationale = rationale
    }
}

/// One component lowering a named threat set on another, as the interface
/// reads it.
public struct ViewedMitigation: Equatable, Sendable {
    public let sourceComponentId: String
    public let targetComponentId: String
    public let threatIds: [String]
    public let reducesRiskBy: Int
    /// `adopted` or `assumed`.
    public let status: String
    /// What a team would do to adopt an assumed edge, or nil.
    public let actionLabel: String?
    public let actionText: String?
    /// Why, or how. Nil when the action states none.
    public let actionNote: String?
    /// The label of the assumption that holds the action up, or nil.
    public let actionBlockedBy: String?
    /// Where the action comes from. Empty when it names none.
    public let actionSources: [String]

    public init(
        sourceComponentId: String,
        targetComponentId: String,
        threatIds: [String],
        reducesRiskBy: Int,
        status: String,
        actionLabel: String? = nil,
        actionText: String? = nil,
        actionNote: String? = nil,
        actionBlockedBy: String? = nil,
        actionSources: [String] = []
    ) {
        self.sourceComponentId = sourceComponentId
        self.targetComponentId = targetComponentId
        self.threatIds = threatIds
        self.reducesRiskBy = reducesRiskBy
        self.status = status
        self.actionLabel = actionLabel
        self.actionText = actionText
        self.actionNote = actionNote
        self.actionBlockedBy = actionBlockedBy
        self.actionSources = actionSources
    }
}

public struct ViewThreatModelResponse: Equatable, Sendable {
    public let name: String
    public let components: [ViewedComponent]
    public let connections: [ViewedConnection]
    /// In drawing order. A later zone wins where two overlap.
    public let zones: [ViewedZone]
    /// What the system takes on trust.
    public let assumptions: [ViewedAssumption]
    /// What a person does with this system, in file order.
    public let useCases: [ViewedUseCase]
    /// What this model does not cover, in file order.
    public let exclusions: [ViewedExclusion]
    /// The named things of value this system holds, in model order.
    public let systemAssets: [ViewedSystemAsset]
    /// The parties outside this team the system depends on, in file order.
    public let thirdParties: [ViewedThirdParty]
    /// The pictures a team keeps beside the diagram the canvas draws, in
    /// file order.
    public let diagrams: [ViewedSystemDiagram]
    /// What the document states about itself.
    public let systemFacts: ViewedSystemFacts
    /// What one component lowers on another.
    public let mitigations: [ViewedMitigation]
    /// The risk level a likelihood finding may answer up to: what the file
    /// states, or `low` when the file states none. The same value
    /// `threatmodeller check` reports for this system.
    public let riskTolerance: String
    /// Whether there is anything to take back or put in again, so a menu item
    /// can dim itself from the same read that draws the canvas.
    public let canUndo: Bool
    public let canRedo: Bool
    /// What Undo would take back, and what Redo would put back, so the Edit
    /// menu reads `Undo Move`. Nil when there is nothing.
    public let undoLabel: String?
    public let redoLabel: String?

    public init(
        name: String,
        components: [ViewedComponent],
        connections: [ViewedConnection],
        zones: [ViewedZone],
        assumptions: [ViewedAssumption] = [],
        useCases: [ViewedUseCase] = [],
        exclusions: [ViewedExclusion] = [],
        systemAssets: [ViewedSystemAsset] = [],
        thirdParties: [ViewedThirdParty] = [],
        diagrams: [ViewedSystemDiagram] = [],
        systemFacts: ViewedSystemFacts = ViewedSystemFacts(),
        mitigations: [ViewedMitigation] = [],
        riskTolerance: String = RiskLevel.low.rawValue,
        canUndo: Bool = false,
        canRedo: Bool = false,
        undoLabel: String? = nil,
        redoLabel: String? = nil
    ) {
        self.name = name
        self.assumptions = assumptions
        self.useCases = useCases
        self.exclusions = exclusions
        self.systemAssets = systemAssets
        self.thirdParties = thirdParties
        self.diagrams = diagrams
        self.systemFacts = systemFacts
        self.mitigations = mitigations
        self.riskTolerance = riskTolerance
        self.components = components
        self.connections = connections
        self.zones = zones
        self.canUndo = canUndo
        self.canRedo = canRedo
        self.undoLabel = undoLabel
        self.redoLabel = redoLabel
    }
}

/// Everything the canvas draws, as plain values. The canvas never reads a
/// gateway, so this use case supplies the drawing.
public struct ViewThreatModel: ViewThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: ViewThreatModelRequest) -> ViewThreatModelResponse {
        let model = models.current()
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)

        return ViewThreatModelResponse(
            name: model.name,
            components: model.components.map { component in
                // A user has no technology, so the lookup is not asked: a
                // custom technology called `user` is not what a user is.
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
            },
            connections: model.connections.map {
                ViewedConnection(
                    id: $0.id.value,
                    sourceComponentId: $0.source.value,
                    targetComponentId: $0.target.value,
                    kindId: $0.kind.rawValue,
                    description: $0.description,
                    carries: $0.carries,
                    tags: $0.tags
                )
            },
            zones: model.zones.map {
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
            },
            assumptions: model.assumptions.map {
                ViewedAssumption(label: $0.label, text: $0.text, owner: $0.owner)
            },
            useCases: model.useCases.map {
                ViewedUseCase(label: $0.label, text: $0.text)
            },
            exclusions: model.exclusions.map {
                ViewedExclusion(label: $0.label, text: $0.text, rationale: $0.rationale)
            },
            systemAssets: model.systemAssets.map {
                ViewedSystemAsset(
                    id: $0.id,
                    name: $0.name,
                    classificationId: $0.classification.rawValue,
                    description: $0.description,
                    owner: $0.owner
                )
            },
            thirdParties: model.thirdParties.map {
                ViewedThirdParty(
                    id: $0.id,
                    name: $0.name,
                    description: $0.description,
                    kindId: $0.kind.rawValue,
                    kindLabel: $0.kind.label,
                    payingCustomer: $0.payingCustomer,
                    uptimeId: $0.uptime.rawValue,
                    uptimeLabel: $0.uptime.label,
                    uptimeNotes: $0.uptimeNotes,
                    owner: $0.owner,
                    link: $0.link
                )
            },
            diagrams: model.diagrams.map {
                ViewedSystemDiagram(label: $0.label, text: $0.text)
            },
            systemFacts: ViewedSystemFacts(
                owner: model.owner,
                description: model.documentFacts.description,
                authors: model.documentFacts.authors,
                version: model.documentFacts.version,
                created: model.documentFacts.created,
                reviewed: model.documentFacts.reviewed,
                links: model.documentFacts.links,
                repositories: model.documentFacts.repositories,
                attributes: model.documentFacts.attributes.map {
                    ViewedSystemAttribute(name: $0.name, value: $0.value)
                }
            ),
            mitigations: model.mitigatesEdges.map { edge in
                ViewedMitigation(
                    sourceComponentId: edge.source.value,
                    targetComponentId: edge.target.value,
                    threatIds: edge.threatIds.map(\.value),
                    reducesRiskBy: edge.reducesRiskBy,
                    status: edge.effectiveStatus.rawValue,
                    actionLabel: edge.action?.label,
                    actionText: edge.action?.text,
                    actionNote: edge.action?.note,
                    actionBlockedBy: edge.action?.blockedBy,
                    actionSources: edge.action?.sources ?? []
                )
            },
            riskTolerance: model.effectiveRiskTolerance.rawValue,
            canUndo: models.canUndo,
            canRedo: models.canRedo,
            undoLabel: models.undoLabel,
            redoLabel: models.redoLabel
        )
    }
}
