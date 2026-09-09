public protocol ListOutdatedLibrariesUseCase {
    func execute(_ request: ListOutdatedLibrariesRequest) -> ListOutdatedLibrariesResponse
}

public struct ListOutdatedLibrariesRequest: Equatable, Sendable {
    public let root: String

    public init(root: String) {
        self.root = root
    }
}

/// What a repository's tags say about one vendored library.
public struct OutdatedLibrary: Equatable, Sendable {
    public let label: String
    /// The tag the lock file records.
    public let tag: String
    /// The newest tag the repository holds, or nil when the recorded tag is
    /// the newest and when nothing could be read.
    public let newestTag: String?
    /// Why the tags could not be read, or nil.
    public let reason: String?

    public init(label: String, tag: String, newestTag: String?, reason: String? = nil) {
        self.label = label
        self.tag = tag
        self.newestTag = newestTag
        self.reason = reason
    }
}

public enum ListOutdatedLibrariesResponse: Equatable, Sendable {
    /// By label, sorted.
    case listed(libraries: [OutdatedLibrary])
    case notAProject(reason: String)
}

/// Says which vendored libraries have a newer tag.
///
/// It reaches a server, so it is the one listing a person asks for rather than
/// one a window runs on its own.
///
/// Tags are compared as text, not as versions, so `v10` sorts before `v9`. The
/// carry-forward note records that.
public struct ListOutdatedLibraries: ListOutdatedLibrariesUseCase {
    private let projects: ProjectSourceGateway
    private let fetcher: LibraryFetching

    public init(projects: ProjectSourceGateway, fetcher: LibraryFetching) {
        self.projects = projects
        self.fetcher = fetcher
    }

    public func execute(_ request: ListOutdatedLibrariesRequest) -> ListOutdatedLibrariesResponse {
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

        let libraries = lock.libraries.map { entry -> OutdatedLibrary in
            do {
                let tags = try fetcher.tags(repository: entry.repository).sorted()
                let newest = tags.last
                return OutdatedLibrary(
                    label: entry.label,
                    tag: entry.tag,
                    newestTag: (newest == entry.tag || newest == nil) ? nil : newest
                )
            } catch let fault as LibraryFetchFault {
                return OutdatedLibrary(
                    label: entry.label,
                    tag: entry.tag,
                    newestTag: nil,
                    reason: fault.message
                )
            } catch {
                return OutdatedLibrary(
                    label: entry.label,
                    tag: entry.tag,
                    newestTag: nil,
                    reason: String(describing: error)
                )
            }
        }
        return .listed(libraries: libraries)
    }
}
