public protocol SaveSystemUseCase {
    func execute(_ request: SaveSystemRequest) -> SaveSystemResponse
}

public struct SaveSystemRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String

    public init(root: String, systemName: String) {
        self.root = root
        self.systemName = systemName
    }
}

public enum SaveSystemResponse: Equatable, Sendable {
    case saved(architecturePath: String)
    case noSuchSystem
    case cannotWrite(reason: String)
}

/// Writes the model on screen back to the files it came from.
public struct SaveSystem: SaveSystemUseCase {
    private let projects: ProjectSourceGateway
    private let exports: ExportArchitectureUseCase
    private let sources: ArchitectureSourceGateway?

    public init(
        projects: ProjectSourceGateway,
        exports: ExportArchitectureUseCase,
        sources: ArchitectureSourceGateway? = nil
    ) {
        self.projects = projects
        self.exports = exports
        self.sources = sources
    }

    public func execute(_ request: SaveSystemRequest) -> SaveSystemResponse {
        do {
            guard let system = try projects.discover(root: request.root)
                .system(named: request.systemName) else {
                return .noSuchSystem
            }

            guard system.isSplit, let sources else {
                try projects.write(
                    exports.execute(ExportArchitectureRequest()).text,
                    to: system.architecturePath
                )
                return .saved(architecturePath: system.architecturePath)
            }

            let held = system.architecturePaths.compactMap { path in
                (try? projects.read(path: path)).map { SourcePart(file: path, text: $0) }
            }
            let read = sources.read(held, named: system.name)

            let written = exports.execute(
                ExportArchitectureRequest(
                    origins: read.origins,
                    headerFile: system.headerPath
                )
            )
            for part in written.parts {
                let already = try? projects.read(path: part.file)
                guard already != part.text else { continue }
                try projects.write(part.text, to: part.file)
            }
            return .saved(architecturePath: system.headerPath)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
    }
}
