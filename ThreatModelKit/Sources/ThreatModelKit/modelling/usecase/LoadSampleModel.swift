public protocol LoadSampleModelUseCase {
    func execute(_ request: LoadSampleModelRequest) -> LoadSampleModelResponse
}

public struct LoadSampleModelRequest: Equatable, Sendable {
    public let sampleId: String
    public init(sampleId: String) { self.sampleId = sampleId }
}

public enum LoadSampleModelResponse: Equatable, Sendable {
    case loaded(name: String)
    case unknownSample
    case unreadable(reason: String)
}

/// Puts a bundled example in front of the user.
///
/// It replaces the model on screen as one change, so a user who did not mean
/// it presses undo once.
public struct LoadSampleModel: LoadSampleModelUseCase {
    private let models: ThreatModelGateway
    private let samples: SampleModelGateway
    private let files: ThreatModelFileGateway

    public init(
        models: ThreatModelGateway,
        samples: SampleModelGateway,
        files: ThreatModelFileGateway
    ) {
        self.models = models
        self.samples = samples
        self.files = files
    }

    public func execute(_ request: LoadSampleModelRequest) -> LoadSampleModelResponse {
        let loaded: ThreatModel
        do {
            loaded = try files.decode(try samples.document(id: request.sampleId))
        } catch SampleModelError.unknownSample {
            return .unknownSample
        } catch {
            return .unreadable(reason: String(describing: error))
        }

        return models.mutate { model in
            model = loaded
            return .loaded(name: loaded.name)
        }
    }
}
