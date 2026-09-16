public protocol SetThirdPartyUseCase {
    func execute(_ request: SetThirdPartyRequest) -> SetThirdPartyResponse
}

public struct SetThirdPartyRequest: Equatable, Sendable {
    /// Names the party. Writing the same id again changes the block that is
    /// there.
    public let id: String
    public let name: String
    public let description: String
    /// A kind id: `saas`, `open_source`, `infrastructure` or `contractor`.
    public let kind: String
    /// Whether the team pays this party for the thing it provides.
    public let payingCustomer: Bool
    /// What happens to this system when the party stops: `none`, `degraded`,
    /// `hard` or `operational`.
    public let uptime: String
    public let uptimeNotes: String
    public let owner: String?
    public let link: String?

    public init(
        id: String,
        name: String,
        description: String = "",
        kind: String = "saas",
        payingCustomer: Bool = false,
        uptime: String,
        uptimeNotes: String = "",
        owner: String? = nil,
        link: String? = nil
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.kind = kind
        self.payingCustomer = payingCustomer
        self.uptime = uptime
        self.uptimeNotes = uptimeNotes
        self.owner = owner
        self.link = link
    }
}

public enum SetThirdPartyResponse: Equatable, Sendable {
    case recorded
    case noId
    case noName
    case unknownKind
    case unknownUptime

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .noId: message = "A third party needs an identifier."
        case .noName: message = "A third party needs a name."
        case .unknownKind:
            message = "A kind is saas, open_source, infrastructure or contractor."
        case .unknownUptime:
            message = "An uptime is none, degraded, hard or operational."
        }
    }
}

/// Writes one `third_party` block into this system's architecture file.
///
/// Language guide section 4.5. A component states which party provides it, so
/// the vendor is written once and read wherever the component goes.
public struct SetThirdParty: SetThirdPartyUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetThirdPartyRequest) -> SetThirdPartyResponse {
        let id = request.id.trimmingWhitespace()
        let name = request.name.trimmingWhitespace()

        guard id.isEmpty == false else { return .noId }
        guard name.isEmpty == false else { return .noName }
        guard let kind = ThirdPartyKind(rawValue: request.kind.trimmingWhitespace()) else {
            return .unknownKind
        }
        guard let uptime = UptimeDependency(rawValue: request.uptime.trimmingWhitespace()) else {
            return .unknownUptime
        }

        let owner = request.owner?.trimmingWhitespace()
        let link = request.link?.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.setThirdParty) { model in
            let written = ThirdParty(
                id: id,
                name: name,
                description: request.description.trimmingWhitespace(),
                kind: kind,
                payingCustomer: request.payingCustomer,
                uptime: uptime,
                uptimeNotes: request.uptimeNotes.trimmingWhitespace(),
                owner: owner?.isEmpty == true ? nil : owner,
                link: link?.isEmpty == true ? nil : link
            )
            if let already = model.thirdParties.firstIndex(where: { $0.id == id }) {
                model.thirdParties[already] = written
            } else {
                model.thirdParties.append(written)
            }
            return .recorded
        }
    }
}

public protocol RemoveThirdPartyUseCase {
    func execute(_ request: RemoveThirdPartyRequest) -> RemoveThirdPartyResponse
}

public struct RemoveThirdPartyRequest: Equatable, Sendable {
    public let id: String

    public init(id: String) {
        self.id = id
    }
}

public enum RemoveThirdPartyResponse: Equatable, Sendable {
    case removed
    case noSuchThirdParty
    /// A component states this party provides it. The value is that
    /// component's name.
    case providesComponent(String)

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .noSuchThirdParty: message = "This system declares no such third party."
        case let .providesComponent(name):
            message = "The component \"\(name)\" states this third party provides it."
        }
    }
}

/// Takes a `third_party` block off this system.
///
/// A component whose `provided_by` names a party nothing declares is an error
/// the parser reports, so the removal is refused while a component names the
/// party. The message names that component, so a person knows where to go.
public struct RemoveThirdParty: RemoveThirdPartyUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: RemoveThirdPartyRequest) -> RemoveThirdPartyResponse {
        let id = request.id.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.removeThirdParty) { model in
            guard let found = model.thirdParties.firstIndex(where: { $0.id == id }) else {
                return .noSuchThirdParty
            }
            if let provided = model.components.first(where: { $0.providedBy == id }) {
                let lookup = TechnologyLookup(model: model, catalogue: catalogue)
                let name = provided.customName
                    ?? lookup.findById(provided.technologyId)?.name
                    ?? provided.technologyId.value
                return .providesComponent(name)
            }
            model.thirdParties.remove(at: found)
            return .removed
        }
    }
}

public protocol SetComponentProviderUseCase {
    func execute(_ request: SetComponentProviderRequest) -> SetComponentProviderResponse
}

public struct SetComponentProviderRequest: Equatable, Sendable {
    public let componentId: String
    /// The third party id, or nil to state that no party provides this
    /// component.
    public let thirdPartyId: String?

    public init(componentId: String, thirdPartyId: String?) {
        self.componentId = componentId
        self.thirdPartyId = thirdPartyId
    }
}

public enum SetComponentProviderResponse: Equatable, Sendable {
    case updated
    case unknownComponent
    case unknownThirdParty

    public func describe(into message: inout String?) {
        switch self {
        case .updated: message = nil
        case .unknownComponent: message = "This system holds no such component."
        case .unknownThirdParty: message = "This system declares no such third party."
        }
    }
}

/// States which third party provides one component.
public struct SetComponentProvider: SetComponentProviderUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetComponentProviderRequest) -> SetComponentProviderResponse {
        let componentId = ComponentId(request.componentId)
        let partyId = request.thirdPartyId?.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.setComponentProvider) { model in
            guard let index = model.components.firstIndex(where: { $0.id == componentId }) else {
                return .unknownComponent
            }
            guard let partyId, partyId.isEmpty == false else {
                model.components[index].providedBy = nil
                return .updated
            }
            guard model.thirdParties.contains(where: { $0.id == partyId }) else {
                return .unknownThirdParty
            }
            model.components[index].providedBy = partyId
            return .updated
        }
    }
}
