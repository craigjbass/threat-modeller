public protocol VerifyLibrariesUseCase {
    func execute(_ request: VerifyLibrariesRequest) -> VerifyLibrariesResponse
}

public struct VerifyLibrariesRequest: Equatable, Sendable {
    public let root: String

    public init(root: String) {
        self.root = root
    }
}

public enum VerifyLibrariesResponse: Equatable, Sendable {
    /// Both lists are file names, sorted.
    case verified(matched: [String], differed: [String])
    case notAProject(reason: String)
}

/// Says whether the library files on disk are the files that were fetched.
///
/// It runs no child process and reaches no server, so a continuous integration
/// job runs it offline.
public struct VerifyLibraries: VerifyLibrariesUseCase {
    private let projects: ProjectSourceGateway

    public init(projects: ProjectSourceGateway) {
        self.projects = projects
    }

    public func execute(_ request: VerifyLibrariesRequest) -> VerifyLibrariesResponse {
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

        var matched: [String] = []
        var differed: [String] = []
        for library in lock.libraries {
            for (fileName, checksum) in library.files {
                let text = try? projects.read(path: ProjectConvention.path(directory, fileName))
                // A file that is not there differs from the file that was
                // fetched, which is what a user needs to know.
                if let text, LibraryLock.checksum(text) == checksum {
                    matched.append(fileName)
                } else {
                    differed.append(fileName)
                }
            }
        }
        return .verified(matched: matched.sorted(), differed: differed.sorted())
    }
}
