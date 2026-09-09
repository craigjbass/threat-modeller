import Testing
import ThreatModelKit

/// The one contract every library fetcher meets.
///
/// `repository` must hold one file, `acme.lib`, at `tag`, and must hold that
/// tag. It must hold at least one file that is not a `.lib` file, so the
/// contract can state that nothing else is read.
public func verifyLibraryFetchingContract(
    _ fetcher: LibraryFetching,
    repository: String,
    tag: String
) {
    let files = (try? fetcher.fetch(repository: repository, tag: tag)) ?? [:]
    #expect(files.keys.sorted() == ["acme.lib"])
    #expect(files["acme.lib"]?.hasPrefix("library \"acme\"") == true)

    #expect(((try? fetcher.tags(repository: repository)) ?? []).contains(tag))

    // A tag the repository does not hold fails, and says so.
    #expect(throws: (any Error).self) {
        _ = try fetcher.fetch(repository: repository, tag: "no-such-tag")
    }

    // A repository is user input, so a value that reads as a flag is refused.
    #expect(throws: LibraryFetchFault.badRepository("--upload-pack=x")) {
        _ = try fetcher.fetch(repository: "--upload-pack=x", tag: tag)
    }
    #expect(throws: LibraryFetchFault.badRepository("--upload-pack=x")) {
        _ = try fetcher.tags(repository: "--upload-pack=x")
    }
}
