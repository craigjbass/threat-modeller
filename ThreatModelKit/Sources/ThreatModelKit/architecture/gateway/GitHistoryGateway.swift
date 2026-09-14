/// Reads the project's git history.
///
/// It reads and never writes: no checkout, no stash, and neither the working
/// tree nor the index is touched. A history that changed the tree it reports on
/// would be a history nobody could trust.
public protocol GitHistoryGateway: Sendable {
    /// The commits that touched any of `paths`, newest first, at most `limit`.
    func commits(root: String, touching paths: [String], limit: Int) throws -> [SourceCommit]
    /// One file as it stood at one commit, or nil when the commit holds no
    /// such file.
    func file(root: String, at hash: String, path: String) throws -> String?
    /// Whether the directory sits inside a git repository at all.
    func isRepository(root: String) -> Bool
}
