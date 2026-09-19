public protocol PreviewSampleModelUseCase {
    func execute(_ request: PreviewSampleModelRequest) -> PreviewSampleModelResponse
}

public struct PreviewSampleModelRequest: Equatable, Sendable {
    public let sampleId: String
    public init(sampleId: String) { self.sampleId = sampleId }
}

public enum PreviewSampleModelResponse: Equatable, Sendable {
    /// The sample as the canvas draws it. Nothing is on screen: the picture is
    /// drawn from this, beside the sample's name.
    case drawn(ViewThreatModelResponse)
    case unknownSample
    case unreadable(reason: String)
}

/// Draws a bundled example without opening it.
public struct PreviewSampleModel: PreviewSampleModelUseCase {
    private let samples: SampleModelGateway
    private let files: ThreatModelFileGateway
    private let catalogue: TechnologyCatalogue

    public init(
        samples: SampleModelGateway,
        files: ThreatModelFileGateway,
        catalogue: TechnologyCatalogue
    ) {
        self.samples = samples
        self.files = files
        self.catalogue = catalogue
    }

    public func execute(_ request: PreviewSampleModelRequest) -> PreviewSampleModelResponse {
        let loaded: ThreatModel
        do {
            loaded = try files.decode(try samples.document(id: request.sampleId))
        } catch SampleModelError.unknownSample {
            return .unknownSample
        } catch {
            return .unreadable(reason: String(describing: error))
        }

        let store = InMemoryThreatModelGateway(loaded)
        return .drawn(
            ViewThreatModel(models: store, catalogue: catalogue)
                .execute(ViewThreatModelRequest())
        )
    }
}
