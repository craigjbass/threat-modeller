public protocol OpenSystemUseCase {
    func execute(_ request: OpenSystemRequest) -> OpenSystemResponse
}

public struct OpenSystemRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String

    public init(root: String, systemName: String) {
        self.root = root
        self.systemName = systemName
    }
}

public enum OpenSystemResponse: Equatable, Sendable {
    case opened(name: String, warnings: [Diagnostic])
    case refused(fileName: String, diagnostics: [Diagnostic])
    case noSuchSystem
    case cannotRead(reason: String)
}

/// Draws one system of a project.
public struct OpenSystem: OpenSystemUseCase {
    private let projects: ProjectSourceGateway
    private let imports: ImportArchitectureUseCase

    public init(projects: ProjectSourceGateway, imports: ImportArchitectureUseCase) {
        self.projects = projects
        self.imports = imports
    }

    public func execute(_ request: OpenSystemRequest) -> OpenSystemResponse {
        let system: ProjectSystem
        do {
            guard let found = try projects.discover(root: request.root)
                .system(named: request.systemName) else {
                return .noSuchSystem
            }
            system = found
        } catch {
            return .cannotRead(reason: String(describing: error))
        }

        let text: String
        do {
            text = try projects.read(path: system.architecturePath)
        } catch {
            return .cannotRead(reason: String(describing: error))
        }

        switch imports.execute(ImportArchitectureRequest(text: text)) {
        case .imported(let name, let warnings):
            return .opened(name: name, warnings: warnings)
        case .refused(let diagnostics):
            return .refused(
                fileName: fileName(of: system.architecturePath),
                diagnostics: diagnostics
            )
        }
    }

    private func fileName(of path: String) -> String {
        path.split(separator: "/").last.map(String.init) ?? path
    }
}
