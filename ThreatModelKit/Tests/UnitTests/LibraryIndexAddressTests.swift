import Foundation
import Testing
@testable import ThreatModelKit
import TestSupport

@Suite("Reading a library index without a credential")
struct LibraryIndexAddressTests {
    // MARK: where the file sits

    @Test func statesThePlainAddressOfAPublicGitHubIndex() {
        #expect(
            LibraryIndex.rawAddress(of: "https://github.com/craigjbass/threat-modeller")
                == "https://raw.githubusercontent.com/craigjbass/threat-modeller/HEAD/index.json"
        )
    }

    @Test func statesThePlainAddressOfAPublicGitLabIndex() {
        #expect(
            LibraryIndex.rawAddress(of: "https://gitlab.com/acme/index")
                == "https://gitlab.com/acme/index/-/raw/HEAD/index.json"
        )
    }

    @Test func readsAnAddressWrittenWithGitOrASlashAtItsEnd() {
        let wanted = "https://raw.githubusercontent.com/acme/index/HEAD/index.json"

        #expect(LibraryIndex.rawAddress(of: "https://github.com/acme/index.git") == wanted)
        #expect(LibraryIndex.rawAddress(of: "https://github.com/acme/index/") == wanted)
    }

    /// An ssh address, a private host and a path deeper than a repository's
    /// root all state nothing, so the read goes through `git`.
    @Test func statesNothingForAnAddressItCannotResolve() {
        #expect(LibraryIndex.rawAddress(of: "git@github.com:acme/index.git") == nil)
        #expect(LibraryIndex.rawAddress(of: "https://git.acme.example/acme/index") == nil)
        #expect(LibraryIndex.rawAddress(of: "https://github.com/acme") == nil)
        #expect(LibraryIndex.rawAddress(of: "https://github.com/acme/index/tree/main") == nil)
        #expect(LibraryIndex.rawAddress(of: "/work/index") == nil)
    }

    @Test func theIndexThisApplicationShipsWithIsReadPlainly() {
        #expect(LibraryIndex.rawAddress(of: ProjectConvention.defaultLibraryIndex) != nil)
    }

    // MARK: what a person reads when it fails

    /// `git`'s own words say what failed and not what to do, so the address
    /// and what a person can check go in front of them.
    @Test func aFailedReadSaysWhatAPersonCanDo() {
        let app = TestDependencies()
        app.libraryIndex.refuse(
            .cannotRead(
                reason: "Could not read Username for 'https://github.com': "
                    + "terminal prompts disabled"
            ),
            at: "https://github.com/acme/index"
        )

        let response = app.readLibraryIndex().execute(
            ReadLibraryIndexRequest(repository: "https://github.com/acme/index")
        )

        guard case .cannotRead(let reason) = response else {
            Issue.record("the index read: \(response)")
            return
        }
        #expect(reason.contains("https://github.com/acme/index"))
        #expect(reason.contains("Check that the address is right"))
        #expect(reason.contains("terminal prompts disabled"))
    }

    @Test func anIndexThisApplicationDoesNotReadSaysSoInItsOwnWords() {
        let app = TestDependencies()
        app.libraryIndex.put("{\"version\": 99, \"libraries\": []}", at: "https://github.com/acme/index")

        let response = app.readLibraryIndex().execute(
            ReadLibraryIndexRequest(repository: "https://github.com/acme/index")
        )

        guard case .cannotRead(let reason) = response else {
            Issue.record("the index read: \(response)")
            return
        }
        #expect(reason.contains("version 99"))
    }
}
