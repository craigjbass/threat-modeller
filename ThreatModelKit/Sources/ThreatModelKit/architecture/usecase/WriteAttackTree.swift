/// Reading, writing and deleting one tree of a system's `.attacktree` file.
///
/// The design in
/// `docs/superpowers/specs/2026-09-15-attack-tree-editor-design.md` decides
/// the editor's shape. These use cases are what it writes through: each reads
/// the file, changes one tree and writes every other tree back unchanged,
/// because a person changing one tree is deciding nothing about the rest.
///
/// One writer states the canonical shape, so a tree written here and the same
/// tree written by `threatmodeller format` are the same bytes.
public protocol ListAttackTreeSourcesUseCase {
    func execute(_ request: ListAttackTreeSourcesRequest) -> ListAttackTreeSourcesResponse
}

public struct ListAttackTreeSourcesRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String

    public init(root: String, systemName: String) {
        self.root = root
        self.systemName = systemName
    }
}

public enum ListAttackTreeSourcesResponse: Equatable, Sendable {
    /// The trees the file states, and the path it was read from. A system
    /// with no file yet states no tree and no fault.
    case listed(trees: [SourceAttackTree], path: String)
    case noSuchSystem
    case cannotRead(reason: String)
}

public struct ListAttackTreeSources: ListAttackTreeSourcesUseCase {
    private let projects: ProjectSourceGateway
    private let sources: AttackTreeSourceGateway

    public init(projects: ProjectSourceGateway, sources: AttackTreeSourceGateway) {
        self.projects = projects
        self.sources = sources
    }

    public func execute(_ request: ListAttackTreeSourcesRequest) -> ListAttackTreeSourcesResponse {
        switch AttackTreeFile.read(
            root: request.root,
            systemName: request.systemName,
            projects: projects,
            sources: sources
        ) {
        case .read(let source, let path):
            return .listed(trees: source.trees, path: path)
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotRead(reason: reason)
        }
    }
}

public protocol WriteAttackTreeUseCase {
    func execute(_ request: WriteAttackTreeRequest) -> WriteAttackTreeResponse
}

public struct WriteAttackTreeRequest: Equatable, Sendable {
    public let root: String
    /// The system's own file name, which names the file to write.
    public let systemName: String
    /// The name the system states for itself, which the file's header names.
    /// Nil writes the file name, for a caller that has read no architecture.
    public let systemDisplayName: String?
    /// The tree to write. A tree whose id the file already states replaces
    /// that one; any other tree is added at the end.
    public let tree: SourceAttackTree

    public init(
        root: String,
        systemName: String,
        systemDisplayName: String? = nil,
        tree: SourceAttackTree
    ) {
        self.root = root
        self.systemName = systemName
        self.systemDisplayName = systemDisplayName
        self.tree = tree
    }
}

public enum WriteAttackTreeResponse: Equatable, Sendable {
    case written(path: String, trees: Int)
    case noSuchSystem
    case noId
    case riskOutsideTheRange
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .written:
            message = nil
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .noId:
            message = "A tree needs an identifier."
        case .riskOutsideTheRange:
            message = "A tree raises risk by 0 to 100."
        case .cannotWrite(let reason):
            message = "That tree could not be written: \(reason)"
        }
    }
}

public struct WriteAttackTree: WriteAttackTreeUseCase {
    private let projects: ProjectSourceGateway
    private let sources: AttackTreeSourceGateway

    public init(projects: ProjectSourceGateway, sources: AttackTreeSourceGateway) {
        self.projects = projects
        self.sources = sources
    }

    public func execute(_ request: WriteAttackTreeRequest) -> WriteAttackTreeResponse {
        let id = request.tree.id.trimmingWhitespace()
        guard id.isEmpty == false else { return .noId }
        guard (0...100).contains(request.tree.raisesRiskBy) else { return .riskOutsideTheRange }

        let held: AttackTreeSource
        let path: String
        switch AttackTreeFile.read(
            root: request.root,
            systemName: request.systemName,
            named: request.systemDisplayName,
            projects: projects,
            sources: sources
        ) {
        case .read(let source, let at):
            held = source
            path = at
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        var trees = held.trees
        if let already = trees.firstIndex(where: { $0.id == id }) {
            trees[already] = request.tree
        } else {
            trees.append(request.tree)
        }

        let written = AttackTreeSource(
            systemName: held.systemName,
            catalogueTag: held.catalogueTag,
            trees: trees
        )
        do {
            try projects.write(sources.write(written), to: path)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .written(path: path, trees: trees.count)
    }
}

public protocol RemoveAttackTreeUseCase {
    func execute(_ request: RemoveAttackTreeRequest) -> RemoveAttackTreeResponse
}

public struct RemoveAttackTreeRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String
    public let treeId: String

    public init(root: String, systemName: String, treeId: String) {
        self.root = root
        self.systemName = systemName
        self.treeId = treeId
    }
}

public enum RemoveAttackTreeResponse: Equatable, Sendable {
    case removed(path: String, trees: Int)
    case noSuchTree
    case noSuchSystem
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .removed:
            message = nil
        case .noSuchTree:
            message = "This system states no such tree."
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .cannotWrite(let reason):
            message = "That tree could not be deleted: \(reason)"
        }
    }
}

public struct RemoveAttackTree: RemoveAttackTreeUseCase {
    private let projects: ProjectSourceGateway
    private let sources: AttackTreeSourceGateway

    public init(projects: ProjectSourceGateway, sources: AttackTreeSourceGateway) {
        self.projects = projects
        self.sources = sources
    }

    public func execute(_ request: RemoveAttackTreeRequest) -> RemoveAttackTreeResponse {
        let held: AttackTreeSource
        let path: String
        switch AttackTreeFile.read(
            root: request.root,
            systemName: request.systemName,
            projects: projects,
            sources: sources
        ) {
        case .read(let source, let at):
            held = source
            path = at
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        guard held.trees.contains(where: { $0.id == request.treeId }) else { return .noSuchTree }
        let trees = held.trees.filter { $0.id != request.treeId }

        do {
            try projects.write(
                sources.write(
                    AttackTreeSource(
                        systemName: held.systemName,
                        catalogueTag: held.catalogueTag,
                        trees: trees
                    )
                ),
                to: path
            )
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .removed(path: path, trees: trees.count)
    }
}

/// One system's `.attacktree` file, read for a change.
///
/// A system with no file yet reads as a file holding no tree, so writing the
/// first tree writes the file.
enum AttackTreeFile {
    enum Read {
        case read(AttackTreeSource, path: String)
        case noSuchSystem
        case cannotRead(reason: String)
    }

    static func read(
        root: String,
        systemName: String,
        named displayName: String? = nil,
        projects: ProjectSourceGateway,
        sources: AttackTreeSourceGateway
    ) -> Read {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: root)
        } catch {
            return .cannotRead(reason: String(describing: error))
        }
        guard let system = layout.systems.first(where: { $0.name == systemName }) else {
            return .noSuchSystem
        }

        let path = system.attackTreePath
        guard projects.exists(path: path) else {
            // A system with no file yet reads as a file holding no tree, and
            // the header names the system the way the architecture does.
            return .read(AttackTreeSource(systemName: displayName ?? systemName), path: path)
        }
        guard let text = try? projects.read(path: path) else {
            return .cannotRead(reason: "\(path) could not be read")
        }
        let found = sources.read(text)
        guard let source = found.source, found.hasErrors == false else {
            return .cannotRead(
                reason: found.diagnostics.first?.described(in: path) ?? "\(path) does not parse"
            )
        }
        return .read(source, path: path)
    }
}
