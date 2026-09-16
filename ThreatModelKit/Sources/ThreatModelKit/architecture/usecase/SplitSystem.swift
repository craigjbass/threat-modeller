import Foundation

public protocol SplitSystemUseCase {
    func execute(_ request: SplitSystemRequest) -> SplitSystemResponse
}

public struct SplitSystemRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String

    public init(root: String, systemName: String) {
        self.root = root
        self.systemName = systemName
    }
}

public enum SplitSystemResponse: Equatable, Sendable {
    case split
    case noSuchSystem
    /// The system's files already sit in the directory form.
    case alreadySplit
    case cannotWrite(reason: String)
}

/// Moves one flat system's files into the directory form:
/// `threatmodel/<name>/arch/`, `controls/` and `attacktree/`, the way
/// `threatmodeller split <system>` moves them.
///
/// It moves files and writes no new content, so a person who reads the
/// change sees moves. The report is deleted, not moved: the next report
/// writes it inside the subproject.
public struct SplitSystem: SplitSystemUseCase {
    private let projects: ProjectSourceGateway

    public init(projects: ProjectSourceGateway) {
        self.projects = projects
    }

    public func execute(_ request: SplitSystemRequest) -> SplitSystemResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        guard let system = layout.system(named: request.systemName) else {
            return .noSuchSystem
        }
        guard system.isSplit == false else { return .alreadySplit }

        let subproject = ProjectConvention.path(layout.directory, request.systemName)

        /// Moves one file into its kind directory under the subproject, or
        /// does nothing when the file is not there. Returns the failure's
        /// reason, or nil for a move that went well.
        func move(_ from: String, _ fileExtension: String) -> String? {
            guard projects.exists(path: from) else { return nil }
            let stem = (from as NSString).lastPathComponent
            let into = ProjectConvention.path(
                ProjectConvention.path(subproject, ProjectConvention.kindDirectory(fileExtension)),
                stem
            )
            do {
                try projects.write(try projects.read(path: from), to: into)
                try projects.delete(path: from)
                return nil
            } catch {
                return String(describing: error)
            }
        }

        if let failure = move(system.architecturePath, ProjectConvention.architectureExtension) {
            return .cannotWrite(reason: failure)
        }
        if let failure = move(system.controlsPath, ProjectConvention.controlsExtension) {
            return .cannotWrite(reason: failure)
        }
        if let failure = move(system.attackTreePath, ProjectConvention.attackTreeExtension) {
            return .cannotWrite(reason: failure)
        }

        try? projects.delete(path: system.reportPath)
        return .split
    }
}
