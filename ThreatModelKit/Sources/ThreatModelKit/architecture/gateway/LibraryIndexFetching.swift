/// Reads a library index.
///
/// An index is a git repository holding one `index.json` at its root, as
/// `docs/superpowers/specs/2026-09-15-library-index-design.md` states. One
/// port, so the window and the executable read an index the same way, and
/// every test answers it with a fake.
public protocol LibraryIndexFetching: Sendable {
    /// The `index.json` the repository holds, as text.
    func fetchIndex(repository: String) throws -> String
}
