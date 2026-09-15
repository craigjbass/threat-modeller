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
///
/// The browser shows the picture of the highlighted sample. The picture comes
/// from the sample's own document, read here, so nothing stores an image and
/// no picture can go stale against the model it shows.
///
/// WARNING: this writes nothing. The model on screen is untouched until a
/// person presses Open, which is `LoadSampleModel`.
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

        // A store of its own, so reading a sample never touches the model in
        // front of the person.
        let store = InMemoryThreatModelGateway(loaded)
        return .drawn(
            ViewThreatModel(models: store, catalogue: catalogue)
                .execute(ViewThreatModelRequest())
        )
    }
}
