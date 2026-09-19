public protocol SetLocalThreatActorUseCase {
    func execute(_ request: SetLocalThreatActorRequest) -> SetLocalThreatActorResponse
}

public struct SetLocalThreatActorRequest: Equatable, Sendable {
    /// Names the actor. Writing the same id again changes the block that is
    /// there.
    public let id: String
    public let name: String
    public let description: String
    public let aliases: [String]
    /// A tier id: `commodity`, `targeted` or `research`. Nil takes the
    /// application's own default, `targeted`.
    public let capability: String?
    public let intent: String
    /// Threat ids.
    public let performs: [String]
    /// MITRE technique ids.
    public let techniques: [String]
    /// A tier id, or nil. An actor that states one performs every threat the
    /// catalogue marks at that tier.
    public let performsCatalogueTier: String?

    public init(
        id: String,
        name: String,
        description: String = "",
        aliases: [String] = [],
        capability: String? = nil,
        intent: String = "",
        performs: [String] = [],
        techniques: [String] = [],
        performsCatalogueTier: String? = nil
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.aliases = aliases
        self.capability = capability
        self.intent = intent
        self.performs = performs
        self.techniques = techniques
        self.performsCatalogueTier = performsCatalogueTier
    }
}

public enum SetLocalThreatActorResponse: Equatable, Sendable {
    case recorded
    case noId
    case noName
    case unknownCapability
    case unknownCatalogueTier

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .noId: message = "A threat actor needs an identifier."
        case .noName: message = "A threat actor needs a name."
        case .unknownCapability:
            message = "A capability is commodity, targeted or research."
        case .unknownCatalogueTier:
            message = "A catalogue tier is commodity, targeted or research."
        }
    }
}

/// Writes one `threat_actor` block into this system's architecture file.
///
/// Threat actors design section 3.2. A block whose id matches a library actor
/// overrides that actor for this system, whole: the block's attributes are the
/// actor, and the library's are not merged in.
public struct SetLocalThreatActor: SetLocalThreatActorUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetLocalThreatActorRequest) -> SetLocalThreatActorResponse {
        let id = request.id.trimmingWhitespace()
        let name = request.name.trimmingWhitespace()

        guard id.isEmpty == false else { return .noId }
        guard name.isEmpty == false else { return .noName }

        let capability: Likelihood
        if let word = request.capability?.trimmingWhitespace(), word.isEmpty == false {
            guard let tier = Likelihood(rawValue: word) else { return .unknownCapability }
            capability = tier
        } else {
            capability = .targeted
        }

        var catalogueTier: Likelihood?
        if let word = request.performsCatalogueTier?.trimmingWhitespace(), word.isEmpty == false {
            guard let tier = Likelihood(rawValue: word) else { return .unknownCatalogueTier }
            catalogueTier = tier
        }

        return models.mutate(label: ChangeLabel.setLocalThreatActor) { model in
            let written = ThreatActor(
                id: ThreatActorId(id),
                name: name,
                description: request.description.trimmingWhitespace(),
                aliases: Self.cleaned(request.aliases),
                capability: capability,
                intent: request.intent.trimmingWhitespace(),
                performs: Self.cleaned(request.performs).map(ThreatId.init),
                techniques: Self.cleaned(request.techniques),
                performsCatalogueTier: catalogueTier
            )
            if let already = model.localActors.firstIndex(where: { $0.id == written.id }) {
                model.localActors[already] = written
            } else {
                model.localActors.append(written)
            }
            return .recorded
        }
    }

    /// Every list this actor writes, cleaned before it is stored.
    private static func cleaned(_ words: [String]) -> [String] {
        words.map { $0.trimmingWhitespace() }.filter { $0.isEmpty == false }
    }
}

public protocol RemoveLocalThreatActorUseCase {
    func execute(_ request: RemoveLocalThreatActorRequest) -> RemoveLocalThreatActorResponse
}

public struct RemoveLocalThreatActorRequest: Equatable, Sendable {
    public let id: String

    public init(id: String) {
        self.id = id
    }
}

public enum RemoveLocalThreatActorResponse: Equatable, Sendable {
    case removed
    case noSuchActor

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .noSuchActor: message = "This system declares no such threat actor."
        }
    }
}

/// Takes a `threat_actor` block off this system.
///
/// The id also comes out of `faces`, but only when no library actor and no
/// ATT&CK group holds it. A block that overrides a library actor leaves a
/// `faces` entry that still names one.
public struct RemoveLocalThreatActor: RemoveLocalThreatActorUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: RemoveLocalThreatActorRequest) -> RemoveLocalThreatActorResponse {
        let id = ThreatActorId(request.id.trimmingWhitespace())
        let heldElsewhere = catalogue.findActor(id) != nil

        return models.mutate(label: ChangeLabel.removeLocalThreatActor) { model in
            guard let found = model.localActors.firstIndex(where: { $0.id == id }) else {
                return .noSuchActor
            }
            model.localActors.remove(at: found)
            if heldElsewhere == false {
                model.facedActorIds.removeAll { $0 == id.value }
            }
            return .removed
        }
    }
}
