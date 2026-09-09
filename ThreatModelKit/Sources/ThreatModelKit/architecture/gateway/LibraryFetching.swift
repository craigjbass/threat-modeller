/// What a fetch can fail with. Each case carries what a person needs to fix it.
public enum LibraryFetchFault: Error, Equatable, Sendable {
    case gitIsNotInstalled
    /// `git`'s own message, which is what tells a user their key is not loaded.
    case cannotRead(reason: String)
    case noLibraryFile
    case badRepository(String)
    case timedOut

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
}
