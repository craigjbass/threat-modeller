import Foundation
import ThreatModelKit

/// Reads a library repository by running `git`.
///
/// A team's access to its own repositories already lives in `ssh-agent`,
/// `~/.ssh/config`, a credential helper and `~/.gitconfig`. Running `git`
/// inherits every one of them, so this application re-implements none of it and
/// holds no credential.
public final class GitLibraryFetcher: LibraryFetching, LibraryIndexFetching, @unchecked Sendable {
    /// How long a `git` command may take before it is killed, so a fetch that
    /// never answers does not stop the window.
    private let timeout: TimeInterval
    private let lock = NSLock()
    /// The `git` this fetcher is running now, so Cancel can stop it.
    private var running: Process?
    /// True when a person pressed Cancel and the child was stopped by that
    /// rather than by the timer.
    private var wasCancelled = false

    /// What reads a plain address. A public index is read this way rather
    /// than cloned, because a clone over HTTPS asks for a username.
    private let downloader: AttackDownloading

    /// The `PATH` `git` is looked for on.
    private let path: String

    public init(
        timeout: TimeInterval = 60,
        downloader: AttackDownloading = CurlDownloader(),
        path: String = ShellPath.value
    ) {
        self.timeout = timeout
        self.downloader = downloader
        self.path = path
    }

    /// Stops the `git` in flight. A fetch that is not running stops nothing.
    public func cancel() {
        lock.lock()
        let child = running
        wasCancelled = true
        lock.unlock()
        child?.terminate()
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

    /// The index one repository holds, as text.
    ///
    /// The same shallow clone a library fetch runs, reading one file rather
    /// than every `.lib`. Nothing in the clone is run.
    public func fetchIndex(repository: String) throws -> String {
        try refuseAFlag(repository)

        // A public index is one file behind a plain address. Reading it that
        // way needs no credential, and a window with no terminal can never
        // answer the username a clone over HTTPS asks for.
        if let address = LibraryIndex.rawAddress(of: repository) {
            do {
                return String(decoding: try downloader.download(from: address), as: UTF8.self)
            } catch {
                // A private repository serves nothing plainly, so the clone
                // below still stands: it uses the access a person has.
                if repository.hasPrefix("https://") == false { throw error }
            }
        }

        let clone = FileManager.default.temporaryDirectory
            .appendingPathComponent("threatmodeller-index-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: clone) }

        _ = try run([
            "clone", "--depth", "1", "--no-tags", "--recurse-submodules=no",
            "--", repository, clone.path
        ])

        guard let text = try? String(
            contentsOf: clone.appendingPathComponent(LibraryIndex.fileName),
            encoding: .utf8
        ) else {
            throw LibraryFetchFault.cannotRead(
                reason: "that repository holds no \(LibraryIndex.fileName) at its root"
            )
        }
        return text
    }

    /// The newest tag, by version. `git` sorts, so this reads the first line
    /// of the answer and never sorts thousands of tags itself.
    public func newestTag(repository: String, wantsPreRelease: Bool) throws -> String? {
        try refuseAFlag(repository)

        let lines = try run(["ls-remote", "--tags", "--sort=-v:refname", "--", repository])
            .split(separator: "\n")

        for line in lines {
            guard let reference = line.split(separator: "\t").last,
                  reference.hasPrefix("refs/tags/") else { continue }
            let tag = reference.dropFirst("refs/tags/".count)
            guard tag.hasSuffix("^{}") == false else { continue }
            guard let version = TagVersion(String(tag)) else { continue }
            guard wantsPreRelease || version.isPreRelease == false else { continue }
            return version.tag
        }
        return nil
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

    /// A repository is user input, so a value that reads as a flag is refused
    /// rather than passed to `git`.
    private func refuseAFlag(_ repository: String) throws {
        if repository.hasPrefix("-") { throw LibraryFetchFault.badRepository(repository) }
    }

    private func run(_ arguments: [String]) throws -> String {
        var environment = ShellPath.environment(path: path, of: ProcessInfo.processInfo.environment)
        // A repository the user cannot read fails and says so, rather than
        // waiting for a password nobody can type.
        environment["GIT_TERMINAL_PROMPT"] = "0"

        lock.lock()
        wasCancelled = false
        lock.unlock()
        defer {
            lock.lock()
            running = nil
            lock.unlock()
        }

        let answer: ChildProcessAnswer
        do {
            answer = try ChildProcess.run(
                "/usr/bin/env",
                ["git"] + arguments,
                environment: environment,
                timeout: timeout,
                beforeItStarts: { child in
                    self.lock.lock()
                    self.running = child
                    self.lock.unlock()
                }
            )
        } catch {
            throw LibraryFetchFault.gitIsNotInstalled
        }

        lock.lock()
        let stoppedByAPerson = wasCancelled
        lock.unlock()
        if stoppedByAPerson { throw LibraryFetchFault.cancelled }
        if answer.timerKilledIt { throw LibraryFetchFault.timedOut }

        guard answer.exitCode == 0 else {
            throw LibraryFetchFault.cannotRead(
                reason: answer.errors.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
        return answer.output
    }
}
