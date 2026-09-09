public protocol ListLibrariesUseCase {
    func execute(_ request: ListLibrariesRequest) -> ListLibrariesResponse
}

public struct ListLibrariesRequest: Equatable, Sendable {
    public let root: String

    public init(root: String) {
        self.root = root
    }
}

/// One library a project holds, as a reader wants to see it.
public struct ListedLibrary: Equatable, Sendable {
    public let label: String
    /// The display name the file states, else the label.
    public let name: String
    public let repository: String
    public let tag: String
    /// True when every one of the library's files matches the lock file.
    public let matchesLock: Bool

    public init(
        label: String,
        name: String,
        repository: String,
        tag: String,
        matchesLock: Bool
    ) {
        self.label = label
        self.name = name
        self.repository = repository
        self.tag = tag
        self.matchesLock = matchesLock
    }
}

public enum ListLibrariesResponse: Equatable, Sendable {
    /// By label, sorted.
    case listed(libraries: [ListedLibrary])
    case notAProject(reason: String)
}

/// Says what libraries a project holds, and whether each matches the lock file.
///
/// It reaches no server, so the window opens the list without a fetch.
public struct ListLibraries: ListLibrariesUseCase {
    private let projects: ProjectSourceGateway
    private let sources: LibrarySourceGateway
    private let verifies: VerifyLibrariesUseCase

    public init(
        projects: ProjectSourceGateway,
        sources: LibrarySourceGateway,
        verifies: VerifyLibrariesUseCase
    ) {
        self.projects = projects
        self.sources = sources
        self.verifies = verifies
    }

    public func execute(_ request: ListLibrariesRequest) -> ListLibrariesResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch ProjectError.notADirectory(let path) {
            return .notAProject(reason: "\(path) is not a directory")
        } catch {
            return .notAProject(reason: String(describing: error))
        }

        let directory = ProjectConvention.path(
            layout.directory,
            ProjectConvention.libraryDirectory
        )
        let lock = LibraryLock.read(
            (try? projects.read(path: ProjectConvention.path(directory, LibraryLock.fileName))) ?? ""
        )

        var differed: Set<String> = []
        if case .verified(_, let files) = verifies.execute(
            VerifyLibrariesRequest(root: request.root)
        ) {
            differed = Set(files)
        }

        let libraries = lock.libraries.map { entry -> ListedLibrary in
            let displayName = entry.files.keys.sorted().lazy.compactMap { fileName -> String? in
                guard let text = try? projects.read(
                    path: ProjectConvention.path(directory, fileName)
                ) else { return nil }
                return sources.read(text).source?.displayName
            }.first ?? entry.label

            return ListedLibrary(
                label: entry.label,
                name: displayName,
                repository: entry.repository,
                tag: entry.tag,
                matchesLock: entry.files.keys.allSatisfy { differed.contains($0) == false }
            )
        }
        return .listed(libraries: libraries)
    }
}
