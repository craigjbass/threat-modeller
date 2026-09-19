import Foundation

/// What the application opens at launch.
///
/// A pure decision, so a test states each case and no test launches anything.
nonisolated enum LaunchChoice: Equatable {
    /// The welcome window, which is what a first launch gets.
    case welcome
    /// The project at that path.
    case project(path: String)

    /// The setting a person turns on to carry on where they left off. It is
    /// off until they do.
    static let reopenKey = "reopenLastProject"

    /// WARNING: a path on the command line wins over everything else. The
    /// interface test opens a project that way, because an open panel cannot
    /// be driven from a test.
    ///
    /// After that, the setting decides: off gives the welcome window, and on
    /// gives the last project, unless that path is no longer there.
    static func choose(
        commandLinePath: String?,
        reopensLastProject: Bool,
        lastProject: String?,
        exists: (String) -> Bool
    ) -> LaunchChoice {
        if let commandLinePath { return .project(path: commandLinePath) }
        guard reopensLastProject, let lastProject, exists(lastProject) else { return .welcome }
        return .project(path: lastProject)
    }
}
