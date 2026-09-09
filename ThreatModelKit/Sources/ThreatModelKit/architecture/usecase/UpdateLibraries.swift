public protocol UpdateLibrariesUseCase {
    func execute(_ request: UpdateLibrariesRequest) -> UpdateLibrariesResponse
}

public struct UpdateLibrariesRequest: Equatable, Sendable {
    public let root: String
    /// One library, or nil for every library the project holds.
    public let label: String?

    public init(root: String, label: String? = nil) {
        self.root = root
        self.label = label
    }
}

public enum UpdateLibrariesResponse: Equatable, Sendable {
    case updated(labels: [String])
    case noSuchLibrary
    case cannotFetch(label: String, reason: String)
    case refused(label: String, reason: String)
    case notAProject(reason: String)
}

/// Fetches every library again at the tag the lock file records.
///
/// It changes no tag: `add` with a new tag is how a team moves version.
public struct UpdateLibraries: UpdateLibrariesUseCase {
    private let projects: ProjectSourceGateway
    private let adds: AddLibraryUseCase

    public init(projects: ProjectSourceGateway, adds: AddLibraryUseCase) {
        self.projects = projects
        self.adds = adds
    }

    public func execute(_ request: UpdateLibrariesRequest) -> UpdateLibrariesResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch ProjectError.notADirectory(let path) {
            return .notAProject(reason: "\(path) is not a directory")
        } catch {
            return .notAProject(reason: String(describing: error))
        }

        let lockPath = ProjectConvention.path(
            ProjectConvention.path(layout.directory, ProjectConvention.libraryDirectory),
            LibraryLock.fileName
        )
        let lock = LibraryLock.read((try? projects.read(path: lockPath)) ?? "")

        let wanted: [LockedLibrary]
        if let label = request.label {
            guard let one = lock.library(labelled: label) else { return .noSuchLibrary }
            wanted = [one]
        } else {
            wanted = lock.libraries
        }

        var updated: [String] = []
        for entry in wanted {
            switch adds.execute(
                AddLibraryRequest(
                    root: request.root,
                    repository: entry.repository,
                    tag: entry.tag
                )
            ) {
            case .added(let label, _):
                updated.append(label)
            case .cannotFetch(let reason):
                return .cannotFetch(label: entry.label, reason: reason)
            case .refused(let reason):
                return .refused(label: entry.label, reason: reason)
            case .notAProject(let reason):
                return .notAProject(reason: reason)
            case .cannotWrite(let reason):
                return .refused(label: entry.label, reason: reason)
            }
        }
        return .updated(labels: updated)
    }
}
