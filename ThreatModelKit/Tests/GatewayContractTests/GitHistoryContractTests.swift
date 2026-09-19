import Foundation
import Testing
import ThreatModelKit
import TestSupport
import FileGateways

/// The fake git history and the one that runs `git` answer the same way.
///
/// The real one builds its own repository in a temporary directory, so no test
/// reads the repository this application is developed in.
@Suite("The git history gateway")
struct GitHistoryContractTests {
    @Test func theFakeHonoursTheContract() throws {
        let fake = FakeGitHistory(root: "/work")
        fake.add(
            hash: "a1b2c3d4e5f6",
            date: Date(timeIntervalSince1970: 1_000_000),
            files: ["threatmodel/payments.arch": "system \"Payments\" { }\n"]
        )
        fake.add(
            hash: "f6e5d4c3b2a1",
            date: Date(timeIntervalSince1970: 2_000_000),
            files: ["threatmodel/payments.arch": "system \"Payments\" { }\n"]
        )

        try verifyGitHistoryContract(
            fake,
            root: "/work",
            path: "threatmodel/payments.arch",
            unheldPath: "threatmodel/nothing.arch"
        )
    }

    @Test func theRealGatewayHonoursTheContract() throws {
        let repository = try aRepository()
        defer { try? FileManager.default.removeItem(atPath: repository) }

        try verifyGitHistoryContract(
            GitHistory(),
            root: repository,
            path: "threatmodel/payments.arch",
            unheldPath: "threatmodel/nothing.arch"
        )

        let path = repository + "/threatmodel/payments.arch"
        try "system \"Payments\" {\n}\n# a third change\n".write(toFile: path, atomically: true, encoding: .utf8)
        _ = try run(["add", "."], in: repository)
        _ = try run(
            ["commit", "--quiet", "-m", "the third commit\nholds a newline in its subject"],
            in: repository
        )

        try verifyGitHistoryKeepsAMultilineSubjectWhole(
            GitHistory(),
            root: repository,
            path: "threatmodel/payments.arch",
            newestSubject: "the third commit holds a newline in its subject",
            olderSubject: "the second"
        )

        _ = try run(["config", "core.pager", "sleep 60"], in: repository)
        try verifyGitHistoryIgnoresAWaitingPager(
            GitHistory(timeout: 5),
            root: repository,
            path: "threatmodel/payments.arch"
        )
    }

    /// Reading the history changes neither the working tree nor the index.
    @Test func theRealGatewayLeavesTheWorkingTreeAlone() throws {
        let repository = try aRepository()
        defer { try? FileManager.default.removeItem(atPath: repository) }

        // An uncommitted change, so a checkout or a stash would show.
        let path = repository + "/threatmodel/payments.arch"
        try "system \"Payments\" { }\n# working\n".write(toFile: path, atomically: true, encoding: .utf8)
        let before = try status(repository)

        let gateway = GitHistory()
        let commits = try gateway.commits(
            root: repository,
            touching: ["threatmodel/payments.arch"],
            limit: 10
        )
        for commit in commits {
            _ = try gateway.file(
                root: repository,
                at: commit.hash,
                path: "threatmodel/payments.arch"
            )
        }

        #expect(try status(repository) == before)
        #expect(
            try String(contentsOfFile: path, encoding: .utf8)
                == "system \"Payments\" { }\n# working\n"
        )
    }

    @Test func saysADirectoryIsNoRepository() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("threatmodeller-history-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        #expect(GitHistory().isRepository(root: directory.path) == false)
    }

    /// A repository with two commits that touched one threat model file.
    private func aRepository() throws -> String {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("threatmodeller-history-\(UUID().uuidString)")
        let threatmodel = directory.appendingPathComponent("threatmodel")
        try FileManager.default.createDirectory(at: threatmodel, withIntermediateDirectories: true)

        _ = try run(["init", "--quiet"], in: directory.path)
        _ = try run(["config", "user.email", "test@example.test"], in: directory.path)
        _ = try run(["config", "user.name", "A Test"], in: directory.path)
        _ = try run(["config", "commit.gpgsign", "false"], in: directory.path)

        let path = threatmodel.appendingPathComponent("payments.arch")
        try "system \"Payments\" { }\n".write(to: path, atomically: true, encoding: .utf8)
        _ = try run(["add", "."], in: directory.path)
        _ = try run(["commit", "--quiet", "-m", "the first"], in: directory.path)

        try "system \"Payments\" {\n}\n".write(to: path, atomically: true, encoding: .utf8)
        _ = try run(["add", "."], in: directory.path)
        _ = try run(["commit", "--quiet", "-m", "the second"], in: directory.path)

        return directory.path
    }

    private func status(_ root: String) throws -> String {
        try run(["status", "--porcelain=v1"], in: root)
    }

    private func run(_ arguments: [String], in directory: String) throws -> String {
        try ChildProcess.run(
            "/usr/bin/env",
            ["git", "-C", directory] + arguments,
            environment: ProcessInfo.processInfo.environment,
            timeout: 60
        ).output
    }
}
