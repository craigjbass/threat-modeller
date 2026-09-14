/// One system a project holds: the architecture file, and the two files that
/// take its name.
public struct ProjectSystem: Equatable, Sendable {
    /// The file stem, which is what a user picks in the systems list.
    public let name: String
    public let architecturePath: String
    /// The answers. It may not exist yet.
    public let controlsPath: String
    /// The report. It is written, not read.
    public let reportPath: String
    /// The attack trees a person wrote for this system. The file may not
    /// exist: a system that states no tree holds no such file.
    public let attackTreePath: String
    /// Who carries each accepted risk and who does each piece of planned work.
    /// The file may not exist: `compile` writes it only when the system
    /// accepts a control, holds a recommendation or declares an action.
    public let governancePath: String

    public init(
        name: String,
        architecturePath: String,
        controlsPath: String,
        reportPath: String,
        attackTreePath: String,
        governancePath: String
    ) {
        self.name = name
        self.architecturePath = architecturePath
        self.controlsPath = controlsPath
        self.reportPath = reportPath
        self.attackTreePath = attackTreePath
        self.governancePath = governancePath
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

    public func system(named name: String) -> ProjectSystem? {
        systems.first { $0.name == name }
    }
}

public enum ProjectError: Error, Equatable, Sendable {
    case notADirectory(path: String)
    case cannotRead(path: String, reason: String)
    case cannotWrite(path: String, reason: String)
}
