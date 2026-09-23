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
    /// The trees the file states, the path it was read from, and the
    /// catalogue tag the file states, or nil for a file that names none. A
    /// system with no file yet states no tree, no tag and no fault.
    case listed(trees: [SourceAttackTree], path: String, catalogueTag: String?)
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
        case .read(let held):
            return .listed(
                trees: held.source.trees,
                path: held.system.attackTreePath,
                catalogueTag: held.source.catalogueTag
            )
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

        let held: AttackTreeFile.Held
        switch AttackTreeFile.read(
            root: request.root,
            systemName: request.systemName,
            named: request.systemDisplayName,
            projects: projects,
            sources: sources
        ) {
        case .read(let found):
            held = found
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        let written = SourceAttackTree(
            id: id,
            name: request.tree.name,
            description: request.tree.description,
            raisesRiskBy: request.tree.raisesRiskBy,
            closedBy: request.tree.closedBy,
            goal: request.tree.goal,
            root: request.tree.root
        )
        let path = held.path(of: id)
        let trees = held.trees(in: path, replacing: written)
        do {
            try projects.write(
                sources.write(
                    AttackTreeSource(
                        systemName: held.source.systemName,
                        catalogueTag: held.source.catalogueTag,
                        trees: trees
                    )
                ),
                to: path
            )
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .written(path: path, trees: trees.count)
    }
}

public protocol TakeAttackTreeCatalogueUseCase {
    func execute(_ request: TakeAttackTreeCatalogueRequest) -> TakeAttackTreeCatalogueResponse
}

public struct TakeAttackTreeCatalogueRequest: Equatable, Sendable {
    public let root: String
    /// The system's own file name, which names the file to write.
    public let systemName: String
    /// The name the system states for itself, which the file's header names
    /// when the file does not exist yet.
    public let systemDisplayName: String?
    /// The catalogue tag to write.
    public let tag: String

    public init(
        root: String,
        systemName: String,
        systemDisplayName: String? = nil,
        tag: String
    ) {
        self.root = root
        self.systemName = systemName
        self.systemDisplayName = systemDisplayName
        self.tag = tag
    }
}

public enum TakeAttackTreeCatalogueResponse: Equatable, Sendable {
    case written(path: String)
    case noSuchSystem
    case cannotWrite(reason: String)

    public func describe(into message: inout String?) {
        switch self {
        case .written:
            message = nil
        case .noSuchSystem:
            message = "This project no longer holds that system."
        case .cannotWrite(let reason):
            message = "The catalogue tag could not be written: \(reason)"
        }
    }
}

/// Takes the catalogue in use into the `.attacktree` file: the tag the file
/// states becomes the tag the application reads its catalogue from. The
/// tree stage offers this the way the architecture stage offers it for the
/// `.arch` file. Every tree the file states is written back unchanged.
public struct TakeAttackTreeCatalogue: TakeAttackTreeCatalogueUseCase {
    private let projects: ProjectSourceGateway
    private let sources: AttackTreeSourceGateway

    public init(projects: ProjectSourceGateway, sources: AttackTreeSourceGateway) {
        self.projects = projects
        self.sources = sources
    }

    public func execute(_ request: TakeAttackTreeCatalogueRequest) -> TakeAttackTreeCatalogueResponse {
        let held: AttackTreeFile.Held
        switch AttackTreeFile.read(
            root: request.root,
            systemName: request.systemName,
            named: request.systemDisplayName,
            projects: projects,
            sources: sources
        ) {
        case .read(let found):
            held = found
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        // The tag is a fact about the system, so every tree file states it.
        // A system with no tree file yet gets the file the header mirrors.
        let paths = held.pathOfTree.values.isEmpty
            ? [held.system.attackTreePath]
            : Set(held.pathOfTree.values).sorted()
        for path in paths {
            let trees = held.pathOfTree.isEmpty ? held.source.trees : held.trees(in: path)
            do {
                try projects.write(
                    sources.write(
                        AttackTreeSource(
                            systemName: held.source.systemName,
                            catalogueTag: request.tag,
                            trees: trees
                        )
                    ),
                    to: path
                )
            } catch {
                return .cannotWrite(reason: String(describing: error))
            }
        }
        return .written(path: paths[0])
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
        let held: AttackTreeFile.Held
        switch AttackTreeFile.read(
            root: request.root,
            systemName: request.systemName,
            projects: projects,
            sources: sources
        ) {
        case .read(let found):
            held = found
        case .noSuchSystem:
            return .noSuchSystem
        case .cannotRead(let reason):
            return .cannotWrite(reason: reason)
        }

        guard held.source.trees.contains(where: { $0.id == request.treeId }) else {
            return .noSuchTree
        }
        let path = held.path(of: request.treeId)
        let trees = held.trees(in: path).filter { $0.id != request.treeId }

        // A file of the split form holds one tree, so taking that tree away
        // leaves no file rather than a file that states nothing.
        if trees.isEmpty, held.system.isSplit {
            do {
                try projects.delete(path: path)
            } catch {
                return .cannotWrite(reason: String(describing: error))
            }
            return .removed(path: path, trees: held.source.trees.count - 1)
        }

        do {
            try projects.write(
                sources.write(
                    AttackTreeSource(
                        systemName: held.source.systemName,
                        catalogueTag: held.source.catalogueTag,
                        trees: trees
                    )
                ),
                to: path
            )
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        return .removed(path: path, trees: held.source.trees.count - 1)
    }
}

/// One system's attack trees, read for a change.
///
/// A flat system holds every tree in one file. A split system gives each tree
/// a file of its own, so the read joins every tree file and remembers which
/// file each tree came from. A system with no file yet reads as no tree, so
/// writing the first tree writes the file.
enum AttackTreeFile {
    struct Held {
        let source: AttackTreeSource
        /// The file each tree came from, by tree identifier.
        let pathOfTree: [String: String]
        /// The system, for the file a new tree goes in.
        let system: ProjectSystem

        /// The file one tree is written in: the file that already holds it,
        /// else the file the system's shape gives it.
        func path(of treeId: String) -> String {
            pathOfTree[treeId] ?? system.treePath(ofTreeId: treeId)
        }

        /// The trees one file holds, with the tree the caller writes put in
        /// place of the tree of that identifier.
        func trees(in path: String, replacing tree: SourceAttackTree) -> [SourceAttackTree] {
            var held = source.trees.filter { pathOfTree[$0.id] == path && $0.id != tree.id }
            held.append(tree)
            return held
        }

        func trees(in path: String) -> [SourceAttackTree] {
            source.trees.filter { pathOfTree[$0.id] == path }
        }
    }

    enum Read {
        case read(Held)
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

        var trees: [SourceAttackTree] = []
        var pathOfTree: [String: String] = [:]
        var name: String?
        var catalogueTag: String?
        for path in system.attackTreePaths where projects.exists(path: path) {
            guard let text = try? projects.read(path: path) else {
                return .cannotRead(reason: "\(path) could not be read")
            }
            let found = sources.read(text)
            guard let source = found.source, found.hasErrors == false else {
                return .cannotRead(
                    reason: found.diagnostics.first?.described(in: path) ?? "\(path) does not parse"
                )
            }
            name = name ?? source.systemName
            catalogueTag = catalogueTag ?? source.catalogueTag
            for tree in source.trees {
                trees.append(tree)
                pathOfTree[tree.id] = path
            }
        }

        return .read(
            Held(
                source: AttackTreeSource(
                    systemName: name ?? displayName ?? systemName,
                    catalogueTag: catalogueTag,
                    trees: trees
                ),
                pathOfTree: pathOfTree,
                system: system
            )
        )
    }
}
