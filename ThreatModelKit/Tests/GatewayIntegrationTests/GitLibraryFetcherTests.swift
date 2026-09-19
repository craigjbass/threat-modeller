import FileGateways
import Foundation
import Testing
import TestSupport
import ThreatModelKit

/// The real fetcher, over a real repository the test builds.
///
/// `git init` in a temporary directory and a clone by path run the real `git`
/// and reach no network, so this proves the gateway without a server.
@Suite("The git library fetcher")
struct GitLibraryFetcherTests {
    private func aRepository() throws -> String {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("library-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try "library \"acme\" { }\n".write(
            to: directory.appendingPathComponent("acme.lib"),
            atomically: true,
            encoding: .utf8
        )
        try "not a library\n".write(
            to: directory.appendingPathComponent("README.md"),
            atomically: true,
            encoding: .utf8
        )

        for arguments in [
            ["init", "--initial-branch=main"],
            ["add", "."],
            ["-c", "user.email=a@b.c", "-c", "user.name=A", "-c", "commit.gpgsign=false",
             "commit", "-m", "one"],
            ["tag", "v1.0.0"]
        ] {
            let answer = try ChildProcess.run(
                "/usr/bin/env",
                ["git", "-C", directory.path] + arguments,
                environment: ProcessInfo.processInfo.environment,
                timeout: 60
            )
            if answer.exitCode != 0 {
                Issue.record("git \(arguments.joined(separator: " ")) said: \(answer.errors)")
            }
        }
        return directory.path
    }

    @Test func meetsTheContract() throws {
        let repository = try aRepository()
        defer { try? FileManager.default.removeItem(atPath: repository) }

        verifyLibraryFetchingContract(
            GitLibraryFetcher(),
            repository: repository,
            tag: "v1.0.0"
        )
    }

    @Test func readsOnlyTheLibraryFiles() throws {
        let repository = try aRepository()
        defer { try? FileManager.default.removeItem(atPath: repository) }

        let files = try GitLibraryFetcher().fetch(repository: repository, tag: "v1.0.0")

        #expect(files.keys.sorted() == ["acme.lib"])
        #expect(files["acme.lib"] == "library \"acme\" { }\n")
    }

    @Test func saysWhatGitSaidWhenTheRepositoryIsNotThere() {
        #expect(throws: (any Error).self) {
            _ = try GitLibraryFetcher().fetch(
                repository: "/no/such/repository",
                tag: "v1.0.0"
            )
        }
    }

    @Test func saysSoWhenARepositoryHoldsNoLibraryFile() throws {
        let repository = try aRepository()
        defer { try? FileManager.default.removeItem(atPath: repository) }
        try FileManager.default.removeItem(
            atPath: (repository as NSString).appendingPathComponent("acme.lib")
        )
        for arguments in [
            ["add", "-A"],
            ["-c", "user.email=a@b.c", "-c", "user.name=A", "-c", "commit.gpgsign=false",
             "commit", "-m", "two"],
            ["tag", "v2.0.0"]
        ] {
            _ = try ChildProcess.run(
                "/usr/bin/env",
                ["git", "-C", repository] + arguments,
                environment: ProcessInfo.processInfo.environment,
                timeout: 60
            )
        }

        #expect(throws: LibraryFetchFault.noLibraryFile) {
            _ = try GitLibraryFetcher().fetch(repository: repository, tag: "v2.0.0")
        }
    }
}

/// A downloader a test fills by hand, so nothing reaches a server.
private final class FakeDownloader: AttackDownloading, @unchecked Sendable {
    private let lock = NSLock()
    private var bytesByAddress: [String: Data] = [:]
    private var askedValue: [String] = []

    /// Every address this downloader was asked for, in order.
    var asked: [String] {
        lock.lock()
        defer { lock.unlock() }
        return askedValue
    }

    func put(_ text: String, at address: String) {
        lock.lock()
        bytesByAddress[address] = Data(text.utf8)
        lock.unlock()
    }

    func download(from address: String) throws -> Data {
        lock.lock()
        askedValue.append(address)
        let bytes = bytesByAddress[address]
        lock.unlock()
        guard let bytes else {
            throw AttackDownloadFault.cannotRead(reason: "nothing is at \(address)")
        }
        return bytes
    }
}

/// Reading a public index needs no credential, which is what a window with no
/// terminal can answer.
@Suite("Reading a library index")
struct GitLibraryIndexTests {
    private let index = """
    {
      "version": 1,
      "libraries": [
        {"label": "acme", "name": "Acme", "repository": "https://github.com/acme/elements"}
      ]
    }

    """

    @Test func readsAPublicIndexFromItsPlainAddressRatherThanCloningIt() throws {
        let downloader = FakeDownloader()
        downloader.put(
            index,
            at: "https://raw.githubusercontent.com/craigjbass/threat-modeller/HEAD/index.json"
        )
        let fetcher = GitLibraryFetcher(downloader: downloader)

        let text = try fetcher.fetchIndex(
            repository: "https://github.com/craigjbass/threat-modeller"
        )

        #expect(try LibraryIndex.read(text).map(\.label) == ["acme"])
        #expect(downloader.asked.count == 1)
    }

    /// A private repository serves nothing plainly, so the clone still
    /// stands: it uses the access a person already has.
    @Test func fallsBackToGitWhenNothingIsServedPlainly() throws {
        let fetcher = GitLibraryFetcher(timeout: 20, downloader: FakeDownloader())

        #expect(throws: (any Error).self) {
            try fetcher.fetchIndex(repository: "https://github.com/acme/no-such-index-12345")
        }
    }

    /// An ssh address is never read plainly.
    @Test func readsAnSshAddressWithGit() {
        let downloader = FakeDownloader()
        let fetcher = GitLibraryFetcher(timeout: 5, downloader: downloader)

        _ = try? fetcher.fetchIndex(repository: "git@github.com:acme/index.git")

        #expect(downloader.asked.isEmpty)
    }
}
