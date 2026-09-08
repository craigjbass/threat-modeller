public protocol ExportArchitectureUseCase {
    func execute(_ request: ExportArchitectureRequest) -> ExportArchitectureResponse
}

public struct ExportArchitectureRequest: Equatable, Sendable {
    public init() {}
}

public struct ExportArchitectureResponse: Equatable, Sendable {
    public let text: String
    public let fileName: String

    public init(text: String, fileName: String) {
        self.text = text
        self.fileName = fileName
    }
}

/// Writes the model as an architecture file.
///
/// Structure only. A component's zone comes from the containment rule, which is
/// derived from the geometry, and no coordinate is written: the picture is
/// drawn from declaration order every time.
public struct ExportArchitecture: ExportArchitectureUseCase {
    private let models: ThreatModelGateway
    private let sources: ArchitectureSourceGateway

    public init(models: ThreatModelGateway, sources: ArchitectureSourceGateway) {
        self.models = models
        self.sources = sources
    }

    public func execute(_ request: ExportArchitectureRequest) -> ExportArchitectureResponse {
        let model = models.current()

        return ExportArchitectureResponse(
            text: sources.write(ArchitectureSourceBuilder.source(from: model)),
            fileName: "\(FileNaming.stem(from: model.name)).arch"
        )
    }
}
