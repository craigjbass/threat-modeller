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
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = ["git"] + arguments
            process.currentDirectoryURL = directory
            process.standardOutput = Pipe()
            let errors = Pipe()
            process.standardError = errors
            try process.run()
            let said = String(
                decoding: errors.fileHandleForReading.readDataToEndOfFile(),
                as: UTF8.self
            )
            process.waitUntilExit()
            if process.terminationStatus != 0 {
                Issue.record("git \(arguments.joined(separator: " ")) said: \(said)")
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
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = ["git"] + arguments
            process.currentDirectoryURL = URL(fileURLWithPath: repository)
            process.standardOutput = Pipe()
            process.standardError = Pipe()
            try process.run()
            process.waitUntilExit()
        }

        #expect(throws: LibraryFetchFault.noLibraryFile) {
            _ = try GitLibraryFetcher().fetch(repository: repository, tag: "v2.0.0")
        }
    }
}
