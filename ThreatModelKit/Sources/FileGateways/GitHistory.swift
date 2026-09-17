import Foundation
import ThreatModelKit

public enum GitHistoryFault: Error, Equatable {
    case gitIsNotInstalled
    case cannotRead(String)
    case timedOut
}

/// Reads a project's git history by running `git`.
///
/// It reads and never writes: `git log` and `git show` touch neither the
/// working tree nor the index. No checkout, no stash, no clone. A history that
/// changed the tree it reports on would be a history nobody could trust.
///
/// `git` runs as a child process rather than through libgit2, because this
/// package builds statically on Linux and ships as one binary; a C dependency
/// would end that.
public struct GitHistory: GitHistoryGateway {
    /// How long one `git` command may take before it is killed.
    private let timeout: TimeInterval

    public init(timeout: TimeInterval = 30) {
        self.timeout = timeout
    }

    public func commits(root: String, touching paths: [String], limit: Int) throws -> [SourceCommit] {
        guard limit > 0 else { return [] }

        // A record separator no commit subject holds, so a subject with a
        // newline in it cannot break the parse.
        let separator = "\u{1F}"
        var arguments = [
            "-C", root,
            "log",
            "--max-count=\(limit)",
            "--date=iso-strict",
            "--pretty=format:%H\(separator)%h\(separator)%an\(separator)%ad\(separator)%s"
        ]
        if paths.isEmpty == false {
            arguments.append("--")
            arguments += paths
        }

        let text = try run(arguments)
        return text
            .split(separator: "\n", omittingEmptySubsequences: true)
            .compactMap { line in
                let parts = line.components(separatedBy: separator)
                guard parts.count == 5, let date = Self.date(from: parts[3]) else { return nil }
                return SourceCommit(
                    hash: parts[0],
                    shortHash: parts[1],
                    author: parts[2],
                    date: date,
                    subject: parts[4]
                )
            }
    }

    public func file(root: String, at hash: String, path: String) throws -> String? {
        // `git show <hash>:<path>` writes the blob to standard output and
        // leaves everything else alone.
        do {
            return try run(["-C", root, "show", "\(hash):\(path)"])
        } catch GitHistoryFault.cannotRead {
            // A commit that holds no such file is not a fault: a project gains
            // files over its life.
            return nil
        }
    }

    public func isRepository(root: String) -> Bool {
        (try? run(["-C", root, "rev-parse", "--is-inside-work-tree"]))?
            .trimmingCharacters(in: .whitespacesAndNewlines) == "true"
    }

    /// The date `--date=iso-strict` writes, which is ISO 8601 with an offset.
    static func date(from text: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: text)
    }

    private final class Killed: @unchecked Sendable {
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

    private func run(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["git"] + arguments

        var environment = ShellPath.environment
        environment["GIT_TERMINAL_PROMPT"] = "0"
        // A pager would wait for a key nobody can press.
        environment["GIT_PAGER"] = "cat"
        process.environment = environment

        let output = Pipe()
        let errors = Pipe()
        process.standardOutput = output
        process.standardError = errors

        do {
            try process.run()
        } catch {
            throw GitHistoryFault.gitIsNotInstalled
        }

        let wasKilled = Killed()
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak process] in
            guard let process, process.isRunning else { return }
            wasKilled.set()
            process.terminate()
        }

        // The pipes are read before the wait, because a command that writes
        // more than one pipe buffer would otherwise never finish.
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let failure = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()

        if wasKilled.value { throw GitHistoryFault.timedOut }
        guard process.terminationStatus == 0 else {
            throw GitHistoryFault.cannotRead(
                failure.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
        return text
    }
}
