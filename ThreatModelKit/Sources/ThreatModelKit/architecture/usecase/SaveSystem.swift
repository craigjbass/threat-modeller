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

/// Writes the model on screen back to the architecture file it came from.
public struct SaveSystem: SaveSystemUseCase {
    private let projects: ProjectSourceGateway
    private let exports: ExportArchitectureUseCase

    public init(projects: ProjectSourceGateway, exports: ExportArchitectureUseCase) {
        self.projects = projects
        self.exports = exports
    }

    public func execute(_ request: SaveSystemRequest) -> SaveSystemResponse {
        do {
            guard let system = try projects.discover(root: request.root)
                .system(named: request.systemName) else {
                return .noSuchSystem
            }

            try projects.write(
                exports.execute(ExportArchitectureRequest()).text,
                to: system.architecturePath
            )
            return .saved(architecturePath: system.architecturePath)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
    }
}
