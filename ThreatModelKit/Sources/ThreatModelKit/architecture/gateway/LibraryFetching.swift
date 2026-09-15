/// What a fetch can fail with. Each case carries what a person needs to fix it.
public enum LibraryFetchFault: Error, Equatable, Sendable {
    case gitIsNotInstalled
    /// `git`'s own message, which is what tells a user their key is not loaded.
    case cannotRead(reason: String)
    case noLibraryFile
    case badRepository(String)
    case timedOut
    /// A person pressed Cancel.
    case cancelled

    public var message: String {
        switch self {
        case .gitIsNotInstalled:
            "git is not installed, so a library cannot be fetched"
        case .cannotRead(let reason):
            reason
        case .noLibraryFile:
            "that repository holds no .lib file at its root"
        case .badRepository(let repository):
            "\"\(repository)\" is not a repository this application reads"
        case .timedOut:
            "the fetch did not answer in time"
        case .cancelled:
            "the fetch was stopped"
        }
    }
}

/// Reads a library repository.
///
/// One port, so the window and the executable fetch the same way, and every
/// test answers it with a fake.
public protocol LibraryFetching: Sendable {
    /// The `.lib` files at the repository's root, by file name.
    func fetch(repository: String, tag: String) throws -> [String: String]
    /// Every tag the repository holds.
    func tags(repository: String) throws -> [String]
    /// Stops whatever this fetcher is running now.
    ///
    /// A fetch runs `git`, and a `git` that is waiting on a server does not
    /// stop because the task that started it was cancelled. A person who
    /// presses Cancel calls this, and the fetch in flight fails with
    /// `cancelled`.
    func cancel()
    /// The newest tag the repository holds, by version, or nil when it holds
    /// no version tag.
    ///
    /// A caller that wants one tag asks for one tag: a repository with
    /// thousands of tags then does the work in the gateway, which can ask
    /// `git` to sort, rather than handing every tag back to be sorted here.
    func newestTag(repository: String, wantsPreRelease: Bool) throws -> String?
}

public extension LibraryFetching {
    /// A fetcher with nothing to stop stops nothing.
    func cancel() {}

    /// The slow answer, for a gateway that cannot sort: read the tags and
    /// pick the newest by version.
    func newestTag(repository: String, wantsPreRelease: Bool) throws -> String? {
        TagVersion.newest(of: try tags(repository: repository), wantsPreRelease: wantsPreRelease)
    }
}
