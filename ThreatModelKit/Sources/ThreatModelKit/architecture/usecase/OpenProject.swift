public protocol OpenProjectUseCase {
    func execute(_ request: OpenProjectRequest) -> OpenProjectResponse
}

public struct OpenProjectRequest: Equatable, Sendable {
    public let root: String
    public init(root: String) { self.root = root }
}

public enum OpenProjectResponse: Equatable, Sendable {
    case opened(systems: [String], directory: String)
    case notAProject(reason: String)
}

/// Reads what a project root holds.
public struct OpenProject: OpenProjectUseCase {
    private let projects: ProjectSourceGateway

    public init(projects: ProjectSourceGateway) {
        self.projects = projects
    }

    public func execute(_ request: OpenProjectRequest) -> OpenProjectResponse {
        do {
            let layout = try projects.discover(root: request.root)
            return .opened(systems: layout.systems.map(\.name), directory: layout.directory)
        } catch ProjectError.notADirectory(let path) {
            return .notAProject(reason: "\(path) is not a directory")
        } catch {
            return .notAProject(reason: String(describing: error))
        }
    }
}
