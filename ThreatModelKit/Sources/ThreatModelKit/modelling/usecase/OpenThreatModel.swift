import Foundation

public protocol OpenThreatModelUseCase {
    func execute(_ request: OpenThreatModelRequest) -> OpenThreatModelResponse
}

public struct OpenThreatModelRequest: Equatable, Sendable {
    public let data: Data
    public init(data: Data) { self.data = data }
}

/// What has moved under a saved model since it was last assessed.
///
/// Spec section 8: the catalogue version stamp lets the application report
/// drift rather than quietly dropping what no longer exists.
public struct ThreatModelDrift: Equatable, Sendable {
    /// The catalogue the model was last assessed against, or nil for a file
    /// that carries no stamp.
    public let savedCatalogueTag: String?
    public let currentCatalogueTag: String
    /// Technologies the model uses that this catalogue no longer holds. Their
    /// components still draw; they raise no threats.
    public let unknownTechnologyIds: [String]

    public init(savedCatalogueTag: String?, currentCatalogueTag: String, unknownTechnologyIds: [String]) {
        self.savedCatalogueTag = savedCatalogueTag
        self.currentCatalogueTag = currentCatalogueTag
        self.unknownTechnologyIds = unknownTechnologyIds
    }

    public var hasDrift: Bool {
        unknownTechnologyIds.isEmpty == false || savedCatalogueTag != currentCatalogueTag
    }
}

public enum OpenThreatModelResponse: Equatable, Sendable {
    case opened(name: String, drift: ThreatModelDrift)
    case unreadable(reason: String)
}

/// Reads a document into this gateway, and says what has drifted.
///
/// Opening is reading: the model's updated time is whatever the file says, not
/// the time it was opened.
public struct OpenThreatModel: OpenThreatModelUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let files: ThreatModelFileGateway

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        files: ThreatModelFileGateway
    ) {
        self.models = models
        self.catalogue = catalogue
        self.files = files
    }

    public func execute(_ request: OpenThreatModelRequest) -> OpenThreatModelResponse {
        let model: ThreatModel
        do {
            model = try files.decode(request.data)
        } catch {
            return .unreadable(reason: String(describing: error))
        }

        models.save(model)

        let unknown = model.components
            .map(\.technologyId)
            .filter { catalogue.findById($0) == nil }
            .map(\.value)

        return .opened(
            name: model.name,
            drift: ThreatModelDrift(
                savedCatalogueTag: model.catalogueVersion?.tag,
                currentCatalogueTag: catalogue.version().tag,
                unknownTechnologyIds: Array(Set(unknown)).sorted()
            )
        )
    }
}
