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
    /// The control answers dropped on open, because the wording they were
    /// minted from has left the catalogue. Nothing is dropped without being
    /// named here.
    public let prunedControlKeys: [String]

    public init(
        savedCatalogueTag: String?,
        currentCatalogueTag: String,
        unknownTechnologyIds: [String],
        prunedControlKeys: [String] = []
    ) {
        self.savedCatalogueTag = savedCatalogueTag
        self.currentCatalogueTag = currentCatalogueTag
        self.unknownTechnologyIds = unknownTechnologyIds
        self.prunedControlKeys = prunedControlKeys
    }

    /// What was dropped and what moved, one line per fact, for a log and for
    /// the drift banner.
    public var diagnostics: [String] {
        var lines: [String] = []
        if savedCatalogueTag != currentCatalogueTag {
            lines.append(
                "the model was last assessed against catalogue "
                    + "\(savedCatalogueTag ?? "no tag") and this build reads \(currentCatalogueTag)"
            )
        }
        if unknownTechnologyIds.isEmpty == false {
            lines.append(
                "\(unknownTechnologyIds.count) technologies are no longer in the catalogue: "
                    + unknownTechnologyIds.joined(separator: ", ")
            )
        }
        if prunedControlKeys.isEmpty == false {
            lines.append(
                "\(prunedControlKeys.count) control answers were dropped, because the control "
                    + "wording they were recorded against has left the catalogue"
            )
        }
        return lines
    }

    public var hasDrift: Bool {
        unknownTechnologyIds.isEmpty == false
            || prunedControlKeys.isEmpty == false
            || savedCatalogueTag != currentCatalogueTag
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
        var model: ThreatModel
        do {
            model = try files.decode(request.data)
        } catch let ThreatModelFileError.unsupportedFormatVersion(found, supported) {
            return .unreadable(reason: """
                A newer build of the application wrote this file. \
                This file holds format version \(found). \
                This build reads up to format version \(supported). \
                Open this file in a newer build of the application.
                """)
        } catch {
            return .unreadable(reason: String(describing: error))
        }

        // A control answer whose wording has left the catalogue reaches
        // nothing, and would travel in every later save. Dropping it on open
        // is the one place the whole model is in hand.
        let pruning = ControlKeyPruning.prune(model, catalogue: catalogue)
        model.controlStatuses = pruning.statuses

        models.save(model)

        // A technology the model defines travels in the file, so it is
        // never drift, however old the catalogue is.
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        let unknown = model.components
            .map(\.technologyId)
            .filter { lookup.findById($0) == nil }
            .map(\.value)

        return .opened(
            name: model.name,
            drift: ThreatModelDrift(
                savedCatalogueTag: model.catalogueVersion?.tag,
                currentCatalogueTag: catalogue.version().tag,
                unknownTechnologyIds: Array(Set(unknown)).sorted(),
                prunedControlKeys: pruning.pruned.map(\.value)
            )
        )
    }
}
