import Foundation

/// Where the threat catalogue is.
///
/// Three answers, in this order:
///
/// 1. the directory `--catalogue <dir>` or `THREATMODELLER_CATALOGUE` names;
/// 2. the directory the running executable sits in, when `Library/` and
///    `Actors/` sit beside it, which is what a release tarball and the
///    application's helper both look like;
/// 3. nil, which means this target's own resource bundle.
///
/// Rule 2 is why a tarball needs no flag, and why a symbolic link from a
/// directory on the user's `PATH` still finds the catalogue: the path is
/// resolved through the link before the directory is read.
///
/// `resolve` and `directoryBeside` take every value they read. A test names
/// the inputs it wants and changes nothing the whole process shares, so a test
/// that reads the catalogue cannot see a value another test set.
public enum CatalogueLocation {
    nonisolated(unsafe) private static var chosen: String?

    /// The running executable.
    public static let executableURL: URL? = Bundle.main.executableURL

    /// The directory to read instead of the bundle, or nil for the bundle.
    public static var directory: String? {
        get {
            resolve(
                chosen: chosen,
                environment: ProcessInfo.processInfo.environment,
                executable: executableURL
            )
        }
        set { chosen = newValue }
    }

    /// The three rules, as one function of its inputs.
    public static func resolve(
        chosen: String?,
        environment: [String: String],
        executable: URL?
    ) -> String? {
        chosen
            ?? environment["THREATMODELLER_CATALOGUE"]
            ?? directoryBeside(executable)
    }

    /// The directory the executable sits in, when the catalogue sits beside it.
    public static func directoryBeside(_ executable: URL?) -> String? {
        guard let executable else { return nil }
        let directory = executable.resolvingSymlinksInPath().deletingLastPathComponent()

        for name in ["Library", "Actors"] {
            var isDirectory: ObjCBool = false
            let path = directory.appendingPathComponent(name).path
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory),
                  isDirectory.boolValue else { return nil }
        }
        return directory.path
    }
}
