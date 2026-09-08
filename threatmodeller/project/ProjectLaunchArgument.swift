import Foundation

/// Reads `-project <path>` from the command line.
///
/// An open panel cannot be driven from an interface test, so the journey names
/// a temporary project this way instead.
nonisolated enum ProjectLaunchArgument {
    static func path(in arguments: [String] = ProcessInfo.processInfo.arguments) -> String? {
        guard let index = arguments.firstIndex(of: "-project"),
              index + 1 < arguments.count else { return nil }
        let path = arguments[index + 1]
        return path.isEmpty ? nil : path
    }
}
