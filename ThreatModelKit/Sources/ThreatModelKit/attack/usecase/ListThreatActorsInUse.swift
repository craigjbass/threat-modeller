public protocol ListThreatActorsInUseUseCase {
    func execute(_ request: ListThreatActorsInUseRequest) -> ListThreatActorsInUseResponse
}

public struct ListThreatActorsInUseRequest: Equatable, Sendable {
    /// True to list the ATT&CK groups only.
    public let mitreOnly: Bool

    public init(mitreOnly: Bool = false) {
        self.mitreOnly = mitreOnly
    }
}

public struct ListedThreatActor: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    /// Other names this actor is known by, which an editor writes back.
    public let aliases: [String]
    public let capabilityLabel: String
    /// The tier id, which is what an editor writes back.
    public let capabilityId: String
    public let intent: String
    /// How many threats in this project's catalogue this actor performs. It
    /// is what says which of the groups touch this model.
    public let threatsPerformed: Int
    /// The names of those threats, in catalogue order.
    public let threatNames: [String]
    /// The ATT&CK groups this actor is, or the groups that use a technique it
    /// uses. Most shared techniques first.
    public let mitreGroups: [String]
    /// True while the system's `faces` list names this actor.
    public let isFaced: Bool
    /// True when the architecture file declares this actor itself.
    public let isLocal: Bool
    /// The threat ids the actor states, which an editor writes back.
    public let performsThreatIds: [String]
    /// The technique ids the actor states, which an editor writes back.
    public let techniques: [String]
    /// The catalogue tier the actor states, or nil.
    public let performsCatalogueTierId: String?

    public init(
        id: String,
        name: String,
        description: String = "",
        aliases: [String] = [],
        capabilityLabel: String,
        capabilityId: String = "",
        intent: String = "",
        threatsPerformed: Int,
        threatNames: [String] = [],
        mitreGroups: [String] = [],
        isFaced: Bool = false,
        isLocal: Bool = false,
        performsThreatIds: [String] = [],
        techniques: [String] = [],
        performsCatalogueTierId: String? = nil
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.aliases = aliases
        self.capabilityLabel = capabilityLabel
        self.capabilityId = capabilityId
        self.intent = intent
        self.threatsPerformed = threatsPerformed
        self.threatNames = threatNames
        self.mitreGroups = mitreGroups
        self.isFaced = isFaced
        self.isLocal = isLocal
        self.performsThreatIds = performsThreatIds
        self.techniques = techniques
        self.performsCatalogueTierId = performsCatalogueTierId
    }
}

public struct ListThreatActorsInUseResponse: Equatable, Sendable {
    /// The faced actors first, then by the count of threats they perform, most
    /// first, then by name.
    public let actors: [ListedThreatActor]

    public init(actors: [ListedThreatActor]) {
        self.actors = actors
    }
}

/// Says which threat actors this project may face, how much of this project's
/// catalogue each one touches, and which ones the open system faces.
public struct ListThreatActorsInUse: ListThreatActorsInUseUseCase {
    private let catalogue: TechnologyCatalogue
    /// The ATT&CK groups on this machine. This verb is a caller that wants
    /// them, so it reads them.
    private let mitre: MitreActorSource?
    /// The open model, or nil when the caller holds none. The executable lists
    /// a project's actors with no model open, and the window lists them with
    /// one.
    private let models: ThreatModelGateway?

    public init(
        catalogue: TechnologyCatalogue,
        mitre: MitreActorSource? = nil,
        models: ThreatModelGateway? = nil
    ) {
        self.catalogue = catalogue
        self.mitre = mitre
        self.models = models
    }

    public func execute(_ request: ListThreatActorsInUseRequest) -> ListThreatActorsInUseResponse {
        let threats = catalogue.everyThreat()
        let model = models?.current()
        let localActors = model?.localActors ?? []
        let faced = Set(model?.everyFacedActorId ?? [])
        let groups = mitre?.actors() ?? []
        let groupsByTechnique = Self.groupNames(by: groups)

        let actors = held(request, local: localActors, groups: groups)
            .map { actor in
                // The score's own rule, so the list and the threat register
                // agree on which threats an actor performs.
                let performed = threats.filter { threat in
                    ActorLikelihood.performers(of: threat, among: [actor]).isEmpty == false
                }
                return ListedThreatActor(
                    id: actor.id.value,
                    name: actor.name,
                    description: actor.description,
                    aliases: actor.aliases,
                    capabilityLabel: actor.capability.label,
                    capabilityId: actor.capability.id,
                    intent: actor.intent,
                    threatsPerformed: performed.count,
                    threatNames: performed.map(\.name),
                    mitreGroups: Self.mitreGroups(of: actor, among: groupsByTechnique),
                    isFaced: faced.contains(actor.id.value),
                    isLocal: localActors.contains { $0.id == actor.id },
                    performsThreatIds: actor.performs.map(\.value),
                    techniques: actor.techniques,
                    performsCatalogueTierId: actor.performsCatalogueTier?.id
                )
            }
            .sorted {
                if $0.isFaced != $1.isFaced { return $0.isFaced }
                return $0.threatsPerformed == $1.threatsPerformed
                    ? $0.name < $1.name
                    : $0.threatsPerformed > $1.threatsPerformed
            }

        return ListThreatActorsInUseResponse(actors: actors)
    }

    /// The actors this list holds. A local block beats an actor of the same id,
    /// whole, which is the rule `ThreatActorLookup` applies.
    private func held(
        _ request: ListThreatActorsInUseRequest,
        local: [ThreatActor],
        groups: [ThreatActor]
    ) -> [ThreatActor] {
        guard request.mitreOnly == false else { return groups }
        let localIds = Set(local.map(\.id))
        return local + (catalogue.threatActors() + groups).filter {
            localIds.contains($0.id) == false
        }
    }

    /// Every group name, by the parent of each technique the group uses.
    private static func groupNames(by groups: [ThreatActor]) -> [String: [String]] {
        var held: [String: [String]] = [:]
        for group in groups {
            for parent in Set(group.techniques.map(ActorLikelihood.parent(of:))) {
                held[parent, default: []].append(group.name)
            }
        }
        return held
    }

    /// The groups this actor is, or the groups that use a technique it uses.
    ///
    /// An actor whose id starts with `mitre-` is a group already, so it states
    /// itself and nothing else.
    private static func mitreGroups(
        of actor: ThreatActor,
        among groupsByTechnique: [String: [String]]
    ) -> [String] {
        if actor.id.value.hasPrefix(MitreActorSource.prefix) { return [actor.name] }

        var shared: [String: Int] = [:]
        for parent in Set(actor.techniques.map(ActorLikelihood.parent(of:))) {
            for name in groupsByTechnique[parent] ?? [] {
                shared[name, default: 0] += 1
            }
        }
        return shared
            .sorted { $0.value == $1.value ? $0.key < $1.key : $0.value > $1.value }
            .map(\.key)
    }
}
