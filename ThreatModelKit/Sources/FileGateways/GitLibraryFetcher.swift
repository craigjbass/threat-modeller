import Foundation
import ThreatModelKit

/// Reads a library repository by running `git`.
///
/// A team's access to its own repositories already lives in `ssh-agent`,
/// `~/.ssh/config`, a credential helper and `~/.gitconfig`. Running `git`
/// inherits every one of them, so this application re-implements none of it and
/// holds no credential.
public struct GitLibraryFetcher: LibraryFetching {
    /// How long a `git` command may take before it is killed, so a fetch that
    /// never answers does not stop the window.
    private let timeout: TimeInterval

    public init(timeout: TimeInterval = 60) {
        self.timeout = timeout
    }

    public func fetch(repository: String, tag: String) throws -> [String: String] {
        try refuseAFlag(repository)

        let clone = FileManager.default.temporaryDirectory
            .appendingPathComponent("threatmodeller-library-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: clone) }

        // `--recurse-submodules=no` keeps a submodule from being fetched, and
        // nothing from the clone is ever run.
        _ = try run([
            "clone", "--depth", "1", "--no-tags", "--recurse-submodules=no",
            "--branch", tag, "--", repository, clone.path
        ])

        let names = ((try? FileManager.default.contentsOfDirectory(atPath: clone.path)) ?? [])
            .filter { $0.hasSuffix(".\(ProjectConvention.libraryExtension)") }
            .sorted()
        guard names.isEmpty == false else { throw LibraryFetchFault.noLibraryFile }

        var files: [String: String] = [:]
        for name in names {
            guard let text = try? String(
                contentsOf: clone.appendingPathComponent(name),
                encoding: .utf8
            ) else {
                throw LibraryFetchFault.cannotRead(reason: "\(name) is not text this application reads")
            }
            files[name] = text
        }
        return files
    }

    public func tags(repository: String) throws -> [String] {
        try refuseAFlag(repository)

        // Each line reads `<sha>\trefs/tags/<tag>`. An annotated tag adds a
        // second line ending `^{}`, which names the same tag.
        return try run(["ls-remote", "--tags", "--", repository])
            .split(separator: "\n")
            .compactMap { line in
                guard let reference = line.split(separator: "\t").last else { return nil }
                guard reference.hasPrefix("refs/tags/") else { return nil }
                let tag = reference.dropFirst("refs/tags/".count)
                return tag.hasSuffix("^{}") ? nil : String(tag)
            }
    }

    /// Whether the timer killed the child, read after the wait.
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

    /// A repository is user input, so a value that reads as a flag is refused
    /// rather than passed to `git`.
    private func refuseAFlag(_ repository: String) throws {
        if repository.hasPrefix("-") { throw LibraryFetchFault.badRepository(repository) }
    }

    private func run(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["git"] + arguments

        var environment = ProcessInfo.processInfo.environment
        // A repository the user cannot read fails and says so, rather than
        // waiting for a password nobody can type.
        environment["GIT_TERMINAL_PROMPT"] = "0"
        process.environment = environment

        let output = Pipe()
        let errors = Pipe()
        process.standardOutput = output
        process.standardError = errors

        do {
            try process.run()
        } catch {
            throw LibraryFetchFault.gitIsNotInstalled
        }

        // A timer kills the child, so a fetch that never answers does not stop
        // the caller. `wasKilled` is what tells the two apart afterwards.
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

        if wasKilled.value { throw LibraryFetchFault.timedOut }

        guard process.terminationStatus == 0 else {
            throw LibraryFetchFault.cannotRead(
                reason: failure.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
        return text
    }
}
