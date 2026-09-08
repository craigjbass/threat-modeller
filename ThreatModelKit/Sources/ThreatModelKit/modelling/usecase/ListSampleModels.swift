public protocol ListSampleModelsUseCase {
    func execute(_ request: ListSampleModelsRequest) -> ListSampleModelsResponse
}

public struct ListSampleModelsRequest: Equatable, Sendable {
    public init() {}
}

public struct ListedSample: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String

    public init(id: String, name: String, description: String) {
        self.id = id
        self.name = name
        self.description = description
    }
}

public struct ListSampleModelsResponse: Equatable, Sendable {
    public let samples: [ListedSample]

    public init(samples: [ListedSample]) {
        self.samples = samples
    }
}

/// What the samples browser lists.
public struct ListSampleModels: ListSampleModelsUseCase {
    private let samples: SampleModelGateway

    public init(samples: SampleModelGateway) {
        self.samples = samples
    }

    public func execute(_ request: ListSampleModelsRequest) -> ListSampleModelsResponse {
        ListSampleModelsResponse(
            samples: samples.all().map {
                ListedSample(id: $0.id, name: $0.name, description: $0.description)
            }
        )
    }
}
