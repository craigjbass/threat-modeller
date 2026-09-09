public protocol AddLibraryUseCase {
    func execute(_ request: AddLibraryRequest) -> AddLibraryResponse
}

public struct AddLibraryRequest: Equatable, Sendable {
    public let root: String
    public let repository: String
    public let tag: String

    public init(root: String, repository: String, tag: String) {
        self.root = root
        self.repository = repository
        self.tag = tag
    }
}

public enum AddLibraryResponse: Equatable, Sendable {
    case added(label: String, files: [String])
    /// The fetch failed. The reason is `git`'s own message.
    case cannotFetch(reason: String)
    /// What was fetched is not a library this application reads.
    case refused(reason: String)
    case notAProject(reason: String)
    case cannotWrite(reason: String)
}

/// Fetches a library into a project and pins it in the lock file.
///
/// It writes nothing until every fetched file parses, so a repository that
/// holds a fault leaves the project as it was.
public struct AddLibrary: AddLibraryUseCase {
    private let projects: ProjectSourceGateway
    private let fetcher: LibraryFetching
    private let sources: LibrarySourceGateway

    public init(
        projects: ProjectSourceGateway,
        fetcher: LibraryFetching,
        sources: LibrarySourceGateway
    ) {
        self.projects = projects
        self.fetcher = fetcher
        self.sources = sources
    }

    public func execute(_ request: AddLibraryRequest) -> AddLibraryResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch ProjectError.notADirectory(let path) {
            return .notAProject(reason: "\(path) is not a directory")
        } catch {
            return .notAProject(reason: String(describing: error))
        }

        let fetched: [String: String]
        do {
            fetched = try fetcher.fetch(repository: request.repository, tag: request.tag)
        } catch let fault as LibraryFetchFault {
            return .cannotFetch(reason: fault.message)
        } catch {
            return .cannotFetch(reason: String(describing: error))
        }

        // Every file must parse before any file is written.
        var labels: Set<String> = []
        var label: String?
        for fileName in fetched.keys.sorted() {
            let read = sources.read(fetched[fileName] ?? "")
            guard let source = read.source else {
                let first = read.diagnostics.first?.message ?? "it did not parse"
                return .refused(reason: "\(fileName): \(first)")
            }
            guard labels.insert(source.label).inserted else {
                return .refused(
                    reason: "\(fileName): this repository declares \"\(source.label)\" twice"
                )
            }
            label = source.label
        }
        guard let label else { return .refused(reason: "that repository holds no library") }

        let directory = ProjectConvention.path(
            layout.directory,
            ProjectConvention.libraryDirectory
        )
        var checksums: [String: String] = [:]
        for (fileName, text) in fetched {
            do {
                try projects.write(text, to: ProjectConvention.path(directory, fileName))
            } catch {
                return .cannotWrite(reason: String(describing: error))
            }
            checksums[fileName] = LibraryLock.checksum(text)
        }

        let entry = LockedLibrary(
            label: label,
            repository: request.repository,
            tag: request.tag,
            files: checksums
        )
        let lockPath = ProjectConvention.path(directory, LibraryLock.fileName)
        let existing = LibraryLock.read((try? projects.read(path: lockPath)) ?? "")
        let lock = LibraryLock(
            libraries: existing.libraries.filter {
                $0.label != label && $0.repository != request.repository
            } + [entry]
        )
        do {
            try projects.write(lock.written(), to: lockPath)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }

        return .added(label: label, files: fetched.keys.sorted())
    }
}
