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

    public init(name: String, architecturePath: String, controlsPath: String, reportPath: String) {
        self.name = name
        self.architecturePath = architecturePath
        self.controlsPath = controlsPath
        self.reportPath = reportPath
    }
}

/// What a project root holds.
public struct ProjectLayout: Equatable, Sendable {
    public let root: String
    /// `<root>/threatmodel` when that directory exists, else `<root>`.
    public let directory: String
    /// By name, sorted, so two reads of one project list the same thing.
    public let systems: [ProjectSystem]

    public init(root: String, directory: String, systems: [ProjectSystem]) {
        self.root = root
        self.directory = directory
        self.systems = systems
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
