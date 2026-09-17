import Foundation
import ThreatModelKit

/// Downloads by running `curl`.
///
/// The executable ships as a static musl binary, and `FoundationNetworking` is
/// neither small nor dependable in that build. `curl` is on every machine that
/// already runs `git`, which the library verbs need, so this asks for nothing
/// new. macOS runs the same child, so there is one path rather than two.
public struct CurlDownloader: AttackDownloading {
    /// Whether the timer killed the child, read after the wait.
    private final class KilledByTheTimer: @unchecked Sendable {
        private let lock = NSLock()
        private var killed = false

        func set() {
            lock.lock()
            defer { lock.unlock() }
            killed = true
        }

        var value: Bool {
            lock.lock()
            defer { lock.unlock() }
            return killed
        }
    }

    /// How long the download may take before it is killed.
    private let timeout: TimeInterval

    public init(timeout: TimeInterval = 600) {
        self.timeout = timeout
    }

    public func download(from address: String) throws -> Data {
        guard address.hasPrefix("https://") else {
            throw AttackDownloadFault.cannotRead(reason: "\(address) is not an https address")
        }

        let into = FileManager.default.temporaryDirectory
            .appendingPathComponent("threatmodeller-attack-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: into) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [
            "curl", "--fail", "--silent", "--show-error", "--location",
            "--output", into.path, "--", address
        ]
        process.environment = ShellPath.environment

        let errors = Pipe()
        process.standardError = errors
        process.standardOutput = Pipe()

        do {
            try process.run()
        } catch {
            throw AttackDownloadFault.curlIsNotInstalled
        }

        let killed = KilledByTheTimer()
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak process] in
            guard let process, process.isRunning else { return }
            killed.set()
            process.terminate()
        }

        let failure = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()

        if killed.value { throw AttackDownloadFault.timedOut }
        guard process.terminationStatus == 0 else {
            throw AttackDownloadFault.cannotRead(
                reason: failure.isEmpty
                    ? "curl exited with code \(process.terminationStatus)"
                    : failure.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
        guard let data = try? Data(contentsOf: into) else {
            throw AttackDownloadFault.cannotRead(reason: "the download wrote no file")
        }
        return data
    }
}
