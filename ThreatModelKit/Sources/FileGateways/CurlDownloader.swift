import Foundation
import ThreatModelKit

/// Downloads by running `curl`.
///
/// The executable ships as a static musl binary, and `FoundationNetworking` is
/// neither small nor dependable in that build. `curl` is on every machine that
/// already runs `git`, which the library verbs need, so this asks for nothing
/// new. macOS runs the same child, so there is one path rather than two.
public struct CurlDownloader: AttackDownloading {
    /// How long the download may take before it is killed.
    private let timeout: TimeInterval

    /// The `PATH` `curl` is looked for on.
    private let path: String

    public init(timeout: TimeInterval = 600, path: String = ShellPath.value) {
        self.timeout = timeout
        self.path = path
    }

    public func download(from address: String) throws -> Data {
        guard address.hasPrefix("https://") else {
            throw AttackDownloadFault.cannotRead(reason: "\(address) is not an https address")
        }

        let into = FileManager.default.temporaryDirectory
            .appendingPathComponent("threatmodeller-attack-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: into) }

        let answer: ChildProcessAnswer
        do {
            answer = try ChildProcess.run(
                "/usr/bin/env",
                [
                    "curl", "--fail", "--silent", "--show-error", "--location",
                    "--output", into.path, "--", address
                ],
                environment: ShellPath.environment(path: path, of: ProcessInfo.processInfo.environment),
                timeout: timeout
            )
        } catch {
            throw AttackDownloadFault.curlIsNotInstalled
        }

        if answer.timerKilledIt { throw AttackDownloadFault.timedOut }
        guard answer.exitCode == 0 else {
            throw AttackDownloadFault.cannotRead(
                reason: answer.errors.isEmpty
                    ? "curl exited with code \(answer.exitCode)"
                    : answer.errors.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
        guard let data = try? Data(contentsOf: into) else {
            throw AttackDownloadFault.cannotRead(reason: "the download wrote no file")
        }
        return data
    }
}
