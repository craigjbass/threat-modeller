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
public enum CatalogueLocation {
    nonisolated(unsafe) private static var chosen: String?

    /// The running executable. A test sets it to say where the binary is.
    nonisolated(unsafe) public static var executableURL: URL? = Bundle.main.executableURL

    /// The directory to read instead of the bundle, or nil for the bundle.
    public static var directory: String? {
        get {
            chosen
                ?? ProcessInfo.processInfo.environment["THREATMODELLER_CATALOGUE"]
                ?? besideTheExecutable
        }
        set { chosen = newValue }
    }

    /// The directory the real executable sits in, when it holds the catalogue.
    private static var besideTheExecutable: String? {
        guard let executableURL else { return nil }
        let directory = executableURL.resolvingSymlinksInPath().deletingLastPathComponent()

        for name in ["Library", "Actors"] {
            var isDirectory: ObjCBool = false
            let path = directory.appendingPathComponent(name).path
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory),
                  isDirectory.boolValue else { return nil }
        }
        return directory.path
    }
}
