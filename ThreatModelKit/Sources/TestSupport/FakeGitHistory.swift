import Foundation
import ThreatModelKit

/// A git history backed by dictionaries. Honours the same contract as the one
/// that runs `git`.
public final class FakeGitHistory: GitHistoryGateway, @unchecked Sendable {
    /// The commits, newest first.
    private var ordered: [SourceCommit]
    /// The files each commit holds, by hash and then by path.
    private var files: [String: [String: String]]
    private var repositories: Set<String>
    /// How many times a caller asked for the commits, so a test can state
    /// that no read ran until it pressed the control that asks for one.
    public private(set) var readCount = 0

    public init(root: String = "/work") {
        ordered = []
        files = [:]
        repositories = [root]
    }

    /// Adds one commit, newer than every commit added before it.
    public func add(
        hash: String,
        author: String = "Craig",
        date: Date,
        subject: String = "",
        files: [String: String]
    ) {
        ordered.insert(
            SourceCommit(hash: hash, author: author, date: date, subject: subject),
            at: 0
        )
        self.files[hash] = files
    }

    /// Makes a directory read as no repository at all.
    public func forget(_ root: String) {
        repositories.remove(root)
    }

    public func commits(root: String, touching paths: [String], limit: Int) throws -> [SourceCommit] {
        readCount += 1
        guard isRepository(root: root) else { return [] }
        let wanted = Set(paths)

        return ordered
            .filter { commit in
                guard wanted.isEmpty == false else { return true }
                return files[commit.hash]?.keys.contains(where: wanted.contains) ?? false
            }
            .prefix(limit)
            .map { $0 }
    }

    public func file(root: String, at hash: String, path: String) throws -> String? {
        guard let index = ordered.firstIndex(where: { $0.hash == hash }) else {
            return files[hash]?[path]
        }
        for commit in ordered[index...] {
            if let text = files[commit.hash]?[path] { return text }
        }
        return nil
    }

    public func isRepository(root: String) -> Bool {
        repositories.contains { root == $0 || root.hasPrefix($0 + "/") }
    }
}
