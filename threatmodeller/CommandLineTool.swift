import Foundation

/// Puts `threatmodeller` on the user's `PATH`.
///
/// The application carries the executable, and this writes one symbolic link to
/// it in the user's own directory. It installs for the person running the
/// application and asks for no password, so it never writes outside their home.
///
/// It never writes over, and never removes, a file it did not write.
@MainActor
struct CommandLineTool {
    enum Status: Equatable {
        /// This build of the application carries no executable, which is what a
        /// build from Xcode looks like until `scripts/embed-cli.sh` runs.
        case notInThisBuild
        case notInstalled(target: String, isOnPath: Bool)
        /// `isCurrent` is false when the link points at another copy of the
        /// application, which happens when a user moves it.
        case installed(at: String, isCurrent: Bool, isOnPath: Bool)
    }

    enum Outcome: Equatable {
        case installed(at: String)
        case removed
        case refused(reason: String)
    }

    /// The application bundle that carries the executable.
    private let bundle: URL
    /// The user's home directory.
    private let home: URL
    /// The `PATH` this user's shell holds.
    private let path: String

    init(
        bundle: URL = Bundle.main.bundleURL,
        home: URL = URL(fileURLWithPath: NSHomeDirectory()),
        path: String = ProcessInfo.processInfo.environment["PATH"] ?? ""
    ) {
        self.bundle = bundle
        self.home = home
        self.path = path
    }

    /// The directory the executable and its catalogue sit in.
    private var helper: URL {
        bundle.appendingPathComponent("Contents/Resources/threatmodeller-cli/threatmodeller")
    }

    /// Where the link goes. `~/.local/bin` is the usual place for one person's
    /// own commands.
    var target: URL {
        home.appendingPathComponent(".local/bin/threatmodeller")
    }

    /// The one line a user adds to their shell profile when the directory is
    /// not on their `PATH` yet.
    var pathLine: String {
        "export PATH=\"$HOME/.local/bin:$PATH\""
    }

    var isTargetOnPath: Bool {
        let directory = target.deletingLastPathComponent().path
        return path.split(separator: ":").contains { candidate in
            // A profile may write the directory with a trailing slash.
            let text = String(candidate)
            return text == directory || text == directory + "/"
        }
    }

    func status() -> Status {
        guard FileManager.default.fileExists(atPath: helper.path) else { return .notInThisBuild }

        guard let destination = try? FileManager.default.destinationOfSymbolicLink(
            atPath: target.path
        ) else {
            return .notInstalled(target: target.path, isOnPath: isTargetOnPath)
        }
        return .installed(
            at: target.path,
            isCurrent: destination == helper.path,
            isOnPath: isTargetOnPath
        )
    }

    func install() -> Outcome {
        guard FileManager.default.fileExists(atPath: helper.path) else {
            return .refused(reason: "This build of the application carries no command line tool.")
        }

        do {
            try FileManager.default.createDirectory(
                at: target.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
        } catch {
            return .refused(
                reason: "\(target.deletingLastPathComponent().path) could not be made: \(error.localizedDescription)"
            )
        }

        // A link this application wrote is replaced. Anything else is left
        // alone: it belongs to somebody else.
        if let existing = try? FileManager.default.destinationOfSymbolicLink(atPath: target.path) {
            _ = existing
            try? FileManager.default.removeItem(at: target)
        } else if FileManager.default.fileExists(atPath: target.path) {
            return .refused(
                reason: "\(target.path) is already there and is not a link this application wrote."
            )
        }

        do {
            try FileManager.default.createSymbolicLink(at: target, withDestinationURL: helper)
        } catch {
            return .refused(reason: "\(target.path) could not be written: \(error.localizedDescription)")
        }
        return .installed(at: target.path)
    }

    func uninstall() -> Outcome {
        guard (try? FileManager.default.destinationOfSymbolicLink(atPath: target.path)) != nil else {
            if FileManager.default.fileExists(atPath: target.path) {
                return .refused(
                    reason: "\(target.path) is not a link this application wrote, so it was left alone."
                )
            }
            return .removed
        }

        do {
            try FileManager.default.removeItem(at: target)
        } catch {
            return .refused(reason: "\(target.path) could not be removed: \(error.localizedDescription)")
        }
        return .removed
    }
}
