public protocol ExportArchitectureUseCase {
    func execute(_ request: ExportArchitectureRequest) -> ExportArchitectureResponse
}

public struct ExportArchitectureRequest: Equatable, Sendable {
    /// Which file each block came from, so a save writes a block back to the
    /// file it was in. Empty writes one file.
    public let origins: [BlockOrigin: String]
    /// The file a block nobody has seen before goes into, which is the header
    /// file of a split system.
    public let headerFile: String?

    public init(origins: [BlockOrigin: String] = [:], headerFile: String? = nil) {
        self.origins = origins
        self.headerFile = headerFile
    }
}

public struct ExportArchitectureResponse: Equatable, Sendable {
    public let text: String
    public let fileName: String
    /// One text per file, for a system split across files. Empty for a flat
    /// system, which is the one `text` above.
    public let parts: [SourcePart]

    public init(text: String, fileName: String, parts: [SourcePart] = []) {
        self.text = text
        self.fileName = fileName
        self.parts = parts
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
        let source = ArchitectureSourceBuilder.source(from: model)

        return ExportArchitectureResponse(
            text: sources.write(source),
            fileName: "\(FileNaming.stem(from: model.name)).arch",
            parts: request.origins.isEmpty
                ? []
                : ArchitectureSourceSplit.parts(
                    of: source,
                    origins: request.origins,
                    headerFile: request.headerFile,
                    sources: sources
                )
        )
    }
}
