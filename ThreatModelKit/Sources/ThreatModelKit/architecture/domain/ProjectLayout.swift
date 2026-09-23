import Foundation

/// One system a project holds: its architecture files, its answers and its
/// report.
///
/// A flat system is one file of each kind, which is what a project holds
/// today. A split system is a directory: its `arch` directory holds the
/// architecture files, its `controls` directory holds the answers, and its
/// `attacktree` directory holds the trees. Either way the system keeps one
/// name, one namespace, one diagram and one report.
public struct ProjectSystem: Equatable, Sendable {
    /// The file stem, or the directory name, which is what a user picks in
    /// the systems list.
    public let name: String
    /// Every architecture file of this system, by file name, sorted. The
    /// order decides declaration order, which decides the picture.
    public let architecturePaths: [String]
    /// The file that holds the `system` block. A flat system's header file is
    /// its one architecture file.
    public let headerPath: String
    /// The answers. A file may not exist yet.
    public let controlsPaths: [String]
    /// The attack trees a person wrote. A file may not exist: a system that
    /// states no tree holds none.
    public let attackTreePaths: [String]
    /// The report. It is written, not read.
    public let reportPath: String
    /// Who carries each accepted risk and who does each piece of planned work.
    /// The file may not exist: `compile` writes it only when the system
    /// accepts a control, holds a recommendation or declares an action.
    public let governancePath: String

    public init(
        name: String,
        architecturePaths: [String],
        headerPath: String,
        controlsPaths: [String],
        attackTreePaths: [String],
        reportPath: String,
        governancePath: String
    ) {
        self.name = name
        self.architecturePaths = architecturePaths
        self.headerPath = headerPath
        self.controlsPaths = controlsPaths
        self.attackTreePaths = attackTreePaths
        self.reportPath = reportPath
        self.governancePath = governancePath
    }

    /// A flat system: one file of each kind, named by the stem.
    public init(
        name: String,
        architecturePath: String,
        controlsPath: String,
        reportPath: String,
        attackTreePath: String,
        governancePath: String
    ) {
        self.init(
            name: name,
            architecturePaths: [architecturePath],
            headerPath: architecturePath,
            controlsPaths: [controlsPath],
            attackTreePaths: [attackTreePath],
            reportPath: reportPath,
            governancePath: governancePath
        )
    }

    /// True when this system is a directory of files rather than one file.
    public var isSplit: Bool { architecturePaths.count > 1 || headerPath.contains("/arch/") }

    public var architecturePath: String { headerPath }

    /// The controls file that mirrors the header file.
    public var controlsPath: String {
        controlsPaths.first { Self.stem(of: $0) == Self.stem(of: headerPath) }
            ?? controlsPaths.first
            ?? controlsPath(mirroring: headerPath)
    }

    /// The attack tree file that mirrors the header file.
    public var attackTreePath: String {
        attackTreePaths.first { Self.stem(of: $0) == Self.stem(of: headerPath) }
            ?? attackTreePaths.first
            ?? treePath(mirroring: headerPath)
    }

    /// The file one attack tree is written in. A split system gives each
    /// tree a file of its own, named after the tree. A flat system holds
    /// every tree in one file.
    public func treePath(ofTreeId treeId: String) -> String {
        guard isSplit else { return attackTreePath }
        let directory = (headerPath as NSString).deletingLastPathComponent
        let subproject = (directory as NSString).deletingLastPathComponent
        return ProjectConvention.path(
            ProjectConvention.path(subproject, ProjectConvention.attackTreeExtension),
            "\(ProjectConvention.stem(forSystemNamed: treeId))"
                + ".\(ProjectConvention.attackTreeExtension)"
        )
    }

    /// The attack tree file that mirrors an architecture file.
    public func treePath(mirroring architecturePath: String) -> String {
        guard isSplit else {
            return Self.beside(architecturePath, ProjectConvention.attackTreeExtension)
        }
        let stem = Self.stem(of: architecturePath)
        let directory = (architecturePath as NSString).deletingLastPathComponent
        let subproject = (directory as NSString).deletingLastPathComponent
        return ProjectConvention.path(
            ProjectConvention.path(subproject, ProjectConvention.attackTreeExtension),
            "\(stem).\(ProjectConvention.attackTreeExtension)"
        )
    }

    /// The controls file an element declared in that architecture file is
    /// answered in. A controls file mirrors an architecture file by stem.
    public func controlsPath(mirroring architecturePath: String) -> String {
        let stem = Self.stem(of: architecturePath)
        if let held = controlsPaths.first(where: { Self.stem(of: $0) == stem }) { return held }
        guard isSplit else {
            return Self.beside(architecturePath, ProjectConvention.controlsExtension)
        }
        let directory = (architecturePath as NSString).deletingLastPathComponent
        let subproject = (directory as NSString).deletingLastPathComponent
        return ProjectConvention.path(
            ProjectConvention.path(subproject, ProjectConvention.controlsExtension),
            "\(stem).\(ProjectConvention.controlsExtension)"
        )
    }

    static func stem(of path: String) -> String {
        ((path as NSString).lastPathComponent as NSString).deletingPathExtension
    }

    private static func beside(_ path: String, _ fileExtension: String) -> String {
        "\((path as NSString).deletingPathExtension).\(fileExtension)"
    }
}

/// What a project root holds.
public struct ProjectLayout: Equatable, Sendable {
    public let root: String
    /// `<root>/threatmodel` when that directory exists, else `<root>`.
    public let directory: String
    /// By name, sorted, so two reads of one project list the same thing.
    public let systems: [ProjectSystem]
    /// The `.lib` files under `<directory>/library`, sorted. Every system in
    /// the project reads every one of them.
    public let libraryPaths: [String]

    public init(
        root: String,
        directory: String,
        systems: [ProjectSystem],
        libraryPaths: [String] = []
    ) {
        self.root = root
        self.directory = directory
        self.systems = systems
        self.libraryPaths = libraryPaths
    }

    /// The rules this project states for itself. One file for the whole
    /// project, and it may not exist.
    public var policyPath: String {
        ProjectConvention.path(directory, ProjectConvention.policyFileName)
    }

    /// The facts about every CVE the project names. One file for the whole
    /// project, and it may not exist.
    public var vulnerabilityLockPath: String {
        ProjectConvention.path(directory, VulnerabilityLock.fileName)
    }

    public func system(named name: String) -> ProjectSystem? {
        systems.first { $0.name == name }
    }
}

public enum ProjectError: Error, Equatable, Sendable {
    case notADirectory(path: String)
    case cannotRead(path: String, reason: String)
    case cannotWrite(path: String, reason: String)
}
