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
    private let applies: ApplyControlAnswersUseCase

    public init(
        projects: ProjectSourceGateway,
        imports: ImportArchitectureUseCase,
        applies: ApplyControlAnswersUseCase
    ) {
        self.projects = projects
        self.imports = imports
        self.applies = applies
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
            // The answers beside the architecture are part of the system, so
            // opening one reads both.
            var everyWarning = warnings
            if projects.exists(path: system.controlsPath),
               let controlsText = try? projects.read(path: system.controlsPath) {
                switch applies.execute(ApplyControlAnswersRequest(text: controlsText)) {
                case .applied(_, let controlWarnings):
                    everyWarning += controlWarnings
                case .refused(let diagnostics):
                    return .refused(
                        fileName: fileName(of: system.controlsPath),
                        diagnostics: diagnostics
                    )
                }
            }
            return .opened(name: name, warnings: everyWarning)
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
