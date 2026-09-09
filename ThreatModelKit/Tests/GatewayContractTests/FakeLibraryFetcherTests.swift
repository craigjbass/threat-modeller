import Testing
import TestSupport

@Suite("The fake library fetcher")
struct FakeLibraryFetcherTests {
    @Test func meetsTheContract() {
        let fetcher = FakeLibraryFetcher()
        fetcher.put(
            ["acme.lib": "library \"acme\" { }\n"],
            repository: "github.com/acme/threat-elements",
            tag: "v1.0.0"
        )

        verifyLibraryFetchingContract(
            fetcher,
            repository: "github.com/acme/threat-elements",
            tag: "v1.0.0"
        )
    }
}
