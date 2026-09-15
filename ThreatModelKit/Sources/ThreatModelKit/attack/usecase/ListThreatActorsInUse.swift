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
    public let capabilityLabel: String
    /// How many threats in this project's catalogue this actor performs. It
    /// is what says which of the groups touch this model.
    public let threatsPerformed: Int

    public init(id: String, name: String, capabilityLabel: String, threatsPerformed: Int) {
        self.id = id
        self.name = name
        self.capabilityLabel = capabilityLabel
        self.threatsPerformed = threatsPerformed
    }
}

public struct ListThreatActorsInUseResponse: Equatable, Sendable {
    /// By the count of threats they perform, most first, then by name.
    public let actors: [ListedThreatActor]

    public init(actors: [ListedThreatActor]) {
        self.actors = actors
    }
}

/// Says which threat actors this project may face, and how much of this
/// project's catalogue each one touches.
public struct ListThreatActorsInUse: ListThreatActorsInUseUseCase {
    private let catalogue: TechnologyCatalogue
    /// The ATT&CK groups on this machine. This verb is a caller that wants
    /// them, so it reads them.
    private let mitre: MitreActorSource?

    public init(catalogue: TechnologyCatalogue, mitre: MitreActorSource? = nil) {
        self.catalogue = catalogue
        self.mitre = mitre
    }

    public func execute(_ request: ListThreatActorsInUseRequest) -> ListThreatActorsInUseResponse {
        let threats = catalogue.everyThreat()

        let held = request.mitreOnly
            ? (mitre?.actors() ?? [])
            : catalogue.threatActors() + (mitre?.actors() ?? [])
        let actors = held
            .map { actor in
                ListedThreatActor(
                    id: actor.id.value,
                    name: actor.name,
                    capabilityLabel: actor.capability.label,
                    threatsPerformed: threats.count { threat in
                        actor.performs.contains(threat.id)
                            || threat.mitreTechniques.contains { technique in
                                actor.techniques.contains { performed in
                                    // A technique matches at parent level, so
                                    // `T1078.004` counts against `T1078`.
                                    technique.id == performed
                                        || technique.id.hasPrefix("\(performed).")
                                        || performed.hasPrefix("\(technique.id).")
                                }
                            }
                    }
                )
            }
            .sorted {
                $0.threatsPerformed == $1.threatsPerformed
                    ? $0.name < $1.name
                    : $0.threatsPerformed > $1.threatsPerformed
            }

        return ListThreatActorsInUseResponse(actors: actors)
    }
}
