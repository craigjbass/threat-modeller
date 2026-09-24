import FileGateways
import Foundation
import Testing
import TestSupport
import ThreatModelKit

/// The one runner every gateway starts a child process with.
@Suite("The child process runner")
struct ChildProcessTests {
    private static let environment = ProcessInfo.processInfo.environment

    /// A directory holding one tool of that name which never exits.
    private func aDirectoryWithAToolThatNeverExits(named name: String) throws -> String {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("slow-tool-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let tool = directory.appendingPathComponent(name)
        try ToolScript.write("#!/bin/sh\nexec /bin/sleep 60\n", to: tool.path)
        return directory.path
    }

    #if os(Linux)
    @Test func aToolWrittenWhileSiblingsSpawnStillRuns() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("written-tools-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let stop = DispatchSemaphore(value: 0)
        let siblings = (0..<8).map { _ in
            Thread {
                while stop.wait(timeout: .now()) == .timedOut {
                    _ = try? ChildProcess.run("/bin/sh", ["-c", "sleep 0.02"], environment: Self.environment, timeout: 5)
                }
            }
        }
        siblings.forEach { $0.start() }
        defer { siblings.forEach { _ in stop.signal() } }

        var refused = 0
        for index in 0..<600 {
            let tool = directory.appendingPathComponent("tool-\(index)")
            try ToolScript.write("#!/bin/sh\necho ok\n", to: tool.path)
            let answer = try ChildProcess.run("/usr/bin/env", [tool.path], environment: Self.environment, timeout: 5)
            if answer.exitCode != 0 || answer.output != "ok\n" { refused += 1 }
        }

        #expect(refused == 0, "\(refused) tools of 600 did not run")
    }
    #endif

    @Test func aChildThatWritesMoreThanOnePipeBufferAnswersWithTheWholeTextAndEnds() throws {
        let answer = try ChildProcess.run(
            "/bin/sh",
            ["-c", "head -c 200000 /dev/zero | tr \"\\0\" a"],
            environment: Self.environment,
            timeout: 20
        )

        #expect(answer.output.count == 200_000)
        #expect(answer.exitCode == 0)
        #expect(answer.timerKilledIt == false)
    }

    @Test func aChildThatWritesMoreThanOnePipeBufferToTheErrorPipeAnswersWithThatWholeTextAndEnds() throws {
        let answer = try ChildProcess.run(
            "/bin/sh",
            ["-c", "head -c 200000 /dev/zero | tr \"\\0\" b 1>&2"],
            environment: Self.environment,
            timeout: 20
        )

        #expect(answer.errors.count == 200_000)
        #expect(answer.exitCode == 0)
    }

    @Test func aChildThatNeverExitsIsKilledByTheTimer() throws {
        let answer = try ChildProcess.run(
            "/bin/sh",
            ["-c", "sleep 60"],
            environment: Self.environment,
            timeout: 0.2
        )

        #expect(answer.timerKilledIt)
    }

    @Test func aChildThatExitsAtOnceReturnsWithoutWaitingOnTheTimer() throws {
        let start = Date()
        let answer = try ChildProcess.run("/usr/bin/false", [], environment: Self.environment, timeout: 5)
        let elapsed = Date().timeIntervalSince(start)

        #expect(answer.exitCode == 1)
        #expect(elapsed < 0.05)
    }

    @Test func aChildThatEndsInTimeIsNotKilledByTheTimer() throws {
        let answer = try ChildProcess.run(
            "/bin/sh",
            ["-c", "echo hello; echo sorry 1>&2; exit 3"],
            environment: Self.environment,
            timeout: 20
        )

        #expect(answer.output == "hello\n")
        #expect(answer.errors == "sorry\n")
        #expect(answer.exitCode == 3)
        #expect(answer.timerKilledIt == false)
    }

    @Test func aGitThatNeverExitsReadsAsAHistoryTimeout() throws {
        let directory = try aDirectoryWithAToolThatNeverExits(named: "git")

        #expect(throws: GitHistoryFault.timedOut) {
            try GitHistory(timeout: 0.2, path: directory)
                .commits(root: "/tmp", touching: [], limit: 5)
        }
    }

    @Test func aGitThatNeverExitsReadsAsALibraryFetchTimeout() throws {
        let directory = try aDirectoryWithAToolThatNeverExits(named: "git")

        #expect(throws: LibraryFetchFault.timedOut) {
            try GitLibraryFetcher(timeout: 0.2, path: directory).tags(repository: "/tmp/none")
        }
    }

    @Test func aVulnxThatNeverExitsReadsAsALookupTimeout() throws {
        let directory = try aDirectoryWithAToolThatNeverExits(named: "vulnx")

        #expect(throws: VulnerabilityLookupFault.timedOut) {
            try VulnxLookup(timeout: 0.2, path: directory)
                .search(VulnerabilityQuery(product: "nginx", version: ""))
        }
    }

    @Test func aCurlThatNeverExitsReadsAsADownloadTimeout() throws {
        let directory = try aDirectoryWithAToolThatNeverExits(named: "curl")

        #expect(throws: AttackDownloadFault.timedOut) {
            try CurlDownloader(timeout: 0.2, path: directory).download(from: "https://example.com/attack.json")
        }
    }

    @Test func aShellThatNeverExitsLeavesTheProcessPath() throws {
        let directory = try aDirectoryWithAToolThatNeverExits(named: "sh")

        let path = ShellPath.read(
            shell: "\(directory)/sh",
            processPath: "/usr/bin:/bin",
            timeout: 0.2
        )

        #expect(path == "/usr/bin:/bin")
    }
}
