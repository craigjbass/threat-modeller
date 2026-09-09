public protocol RemoveLibraryUseCase {
    func execute(_ request: RemoveLibraryRequest) -> RemoveLibraryResponse
}

public struct RemoveLibraryRequest: Equatable, Sendable {
    public let root: String
    public let label: String
    /// True removes the library even while a system names one of its
    /// technologies.
    public let isForced: Bool

    public init(root: String, label: String, isForced: Bool = false) {
        self.root = root
        self.label = label
        self.isForced = isForced
    }
}

public enum RemoveLibraryResponse: Equatable, Sendable {
    case removed(files: [String])
    /// The systems that name one of the library's technologies, sorted.
    case inUse(systems: [String])
    case noSuchLibrary
    case notAProject(reason: String)
    case cannotWrite(reason: String)
}

/// Deletes a library's files and its lock entry.
///
/// It refuses while a system names one of the library's technologies, because
/// removing it would leave that system holding a technology nothing defines.
public struct RemoveLibrary: RemoveLibraryUseCase {
    private let projects: ProjectSourceGateway
    private let architectureSources: ArchitectureSourceGateway

    public init(projects: ProjectSourceGateway, architectureSources: ArchitectureSourceGateway) {
        self.projects = projects
        self.architectureSources = architectureSources
    }

    public func execute(_ request: RemoveLibraryRequest) -> RemoveLibraryResponse {
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
        let lockPath = ProjectConvention.path(directory, LibraryLock.fileName)
        let lock = LibraryLock.read((try? projects.read(path: lockPath)) ?? "")
        guard let entry = lock.library(labelled: request.label) else { return .noSuchLibrary }

        if request.isForced == false {
            let users = systemsNaming(request.label, in: layout)
            guard users.isEmpty else { return .inUse(systems: users) }
        }

        for fileName in entry.files.keys.sorted() {
            do {
                try projects.delete(path: ProjectConvention.path(directory, fileName))
            } catch {
                return .cannotWrite(reason: String(describing: error))
            }
        }

        let remaining = LibraryLock(
            libraries: lock.libraries.filter { $0.label != request.label }
        )
        do {
            try projects.write(remaining.written(), to: lockPath)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }

        return .removed(files: entry.files.keys.sorted())
    }

    /// A system names a library when a component's technology carries the
    /// library's prefix.
    private func systemsNaming(_ label: String, in layout: ProjectLayout) -> [String] {
        let prefix = "\(label)-"
        return layout.systems.compactMap { system in
            guard let text = try? projects.read(path: system.architecturePath),
                  let source = architectureSources.read(text).source else { return nil }
            let names = source.everyComponent.contains { $0.technologyId.hasPrefix(prefix) }
            return names ? system.name : nil
        }
        .sorted()
    }
}
