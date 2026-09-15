public protocol SetSystemAssetUseCase {
    func execute(_ request: SetSystemAssetRequest) -> SetSystemAssetResponse
}

public struct SetSystemAssetRequest: Equatable, Sendable {
    /// Names the asset. Writing the same id again changes the one that is
    /// there.
    public let id: String
    public let name: String
    /// A classification id, taking the words a component's data takes.
    public let classification: String
    public let description: String
    public let owner: String?

    public init(
        id: String,
        name: String,
        classification: String,
        description: String = "",
        owner: String? = nil
    ) {
        self.id = id
        self.name = name
        self.classification = classification
        self.description = description
        self.owner = owner
    }
}

public enum SetSystemAssetResponse: Equatable, Sendable {
    case recorded
    case noId
    case noName
    case unknownClassification

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .noId: message = "An asset needs an identifier."
        case .noName: message = "An asset needs a name."
        case .unknownClassification:
            message = "This project holds no such classification."
        }
    }
}

/// Writes down one named thing of value the system holds.
///
/// Language guide section 4.2. A component states which of these it holds, and
/// a connection states which it carries, so the classification is written once
/// and read wherever the asset goes.
public struct SetSystemAsset: SetSystemAssetUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue

    public init(models: ThreatModelGateway, catalogue: TechnologyCatalogue) {
        self.models = models
        self.catalogue = catalogue
    }

    public func execute(_ request: SetSystemAssetRequest) -> SetSystemAssetResponse {
        let id = request.id.trimmingWhitespace()
        let name = request.name.trimmingWhitespace()
        let owner = request.owner?.trimmingWhitespace()

        guard id.isEmpty == false else { return .noId }
        guard name.isEmpty == false else { return .noName }
        guard let classification = DataSensitivity.validated(
            request.classification,
            in: catalogue.classifications()
        ) else {
            return .unknownClassification
        }

        return models.mutate(label: ChangeLabel.setSystemAsset) { model in
            let written = SystemAsset(
                id: id,
                name: name,
                classification: classification,
                description: request.description.trimmingWhitespace(),
                owner: owner?.isEmpty == true ? nil : owner
            )
            if let already = model.systemAssets.firstIndex(where: { $0.id == id }) {
                model.systemAssets[already] = written
            } else {
                model.systemAssets.append(written)
            }
            return .recorded
        }
    }
}

public protocol RemoveSystemAssetUseCase {
    func execute(_ request: RemoveSystemAssetRequest) -> RemoveSystemAssetResponse
}

public struct RemoveSystemAssetRequest: Equatable, Sendable {
    public let id: String

    public init(id: String) {
        self.id = id
    }
}

public enum RemoveSystemAssetResponse: Equatable, Sendable {
    case removed
    case noSuchAsset

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .noSuchAsset: message = "This system holds no such asset."
        }
    }
}

/// Takes an asset off the system, and off everything that held or carried it.
/// A component holding an asset nothing declares would be a file nobody can
/// read again.
public struct RemoveSystemAsset: RemoveSystemAssetUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveSystemAssetRequest) -> RemoveSystemAssetResponse {
        let id = request.id.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.removeSystemAsset) { model in
            guard let found = model.systemAssets.firstIndex(where: { $0.id == id }) else {
                return .noSuchAsset
            }
            model.systemAssets.remove(at: found)
            for index in model.components.indices {
                model.components[index].holds.removeAll { $0 == id }
            }
            for index in model.connections.indices {
                model.connections[index].carries.removeAll { $0 == id }
            }
            return .removed
        }
    }
}

public protocol SetConnectionAssetsUseCase {
    func execute(_ request: SetConnectionAssetsRequest) -> SetConnectionAssetsResponse
}

public struct SetConnectionAssetsRequest: Equatable, Sendable {
    public let connectionId: String
    /// The system asset ids this connection carries.
    public let carries: [String]

    public init(connectionId: String, carries: [String]) {
        self.connectionId = connectionId
        self.carries = carries
    }
}

public enum SetConnectionAssetsResponse: Equatable, Sendable {
    case updated
    case unknownConnection
    case unknownAsset

    public func describe(into message: inout String?) {
        switch self {
        case .updated: message = nil
        case .unknownConnection: message = "This system holds no such connection."
        case .unknownAsset: message = "This system declares no such asset."
        }
    }
}

/// States what one connection carries.
public struct SetConnectionAssets: SetConnectionAssetsUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetConnectionAssetsRequest) -> SetConnectionAssetsResponse {
        let connectionId = ConnectionId(request.connectionId)

        return models.mutate(label: ChangeLabel.setConnectionAssets) { model in
            guard let index = model.connections.firstIndex(where: { $0.id == connectionId }) else {
                return .unknownConnection
            }
            let declared = Set(model.systemAssets.map(\.id))
            guard request.carries.allSatisfy(declared.contains) else { return .unknownAsset }
            model.connections[index].carries = request.carries
            return .updated
        }
    }
}
