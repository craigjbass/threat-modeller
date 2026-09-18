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
    /// The `PATH` `git` is looked for on.
    private let path: String

    public init(timeout: TimeInterval = 30, path: String = ShellPath.value) {
        self.timeout = timeout
        self.path = path
    }

    public func commits(root: String, touching paths: [String], limit: Int) throws -> [SourceCommit] {
        guard limit > 0 else { return [] }

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

    private func run(_ arguments: [String]) throws -> String {
        var environment = ShellPath.environment(path: path, of: ProcessInfo.processInfo.environment)
        environment["GIT_TERMINAL_PROMPT"] = "0"
        environment["GIT_PAGER"] = "cat"

        let answer: ChildProcessAnswer
        do {
            answer = try ChildProcess.run(
                "/usr/bin/env",
                ["git"] + arguments,
                environment: environment,
                timeout: timeout
            )
        } catch {
            throw GitHistoryFault.gitIsNotInstalled
        }

        if answer.timerKilledIt { throw GitHistoryFault.timedOut }
        guard answer.exitCode == 0 else {
            throw GitHistoryFault.cannotRead(
                answer.errors.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
        return answer.output
    }
}
