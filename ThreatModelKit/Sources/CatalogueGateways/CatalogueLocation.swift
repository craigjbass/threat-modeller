import Foundation

/// Where the threat catalogue is.
///
/// On macOS it is in this target's resource bundle. A Linux binary ships the
/// catalogue as a directory beside it, and a distribution package may put it
/// somewhere else, so `--catalogue <dir>` and `THREATMODELLER_CATALOGUE` name
/// it. The directory holds `Library/` and `Actors/`, the way the bundle does.
public enum CatalogueLocation {
    nonisolated(unsafe) private static var chosen: String?

    /// The directory to read instead of the bundle, or nil for the bundle.
    public static var directory: String? {
        get { chosen ?? ProcessInfo.processInfo.environment["THREATMODELLER_CATALOGUE"] }
        set { chosen = newValue }
    }
}
