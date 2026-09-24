import CommandLineApplication
import FileGateways
import Foundation
import Testing
import TestSupport

/// Whether the built `threatmodeller` executable starts a shell before it
/// reads its arguments.
///
/// `ShellPath.value` is a static, so once one test in this process forces it,
/// every later test reads the cached answer instead of asking a shell again.
/// A fresh process is the only way to prove no code path forces it before a
/// verb needs one, so this drives the real built executable rather than the
/// in-process `CommandLineApplication`.
@Suite("The executable's startup")
struct CommandLineStartupTests {
    @Test func withNoArgumentsItStartsNoShell() throws {
        let marker = FileManager.default.temporaryDirectory
            .appendingPathComponent("shell-marker-\(UUID().uuidString)")
        let shell = FileManager.default.temporaryDirectory
            .appendingPathComponent("marking-shell-\(UUID().uuidString).sh")
        try ToolScript.write("#!/bin/sh\ntouch \"\(marker.path)\"\nexit 0\n", to: shell.path)
        defer {
            try? FileManager.default.removeItem(at: shell)
            try? FileManager.default.removeItem(at: marker)
        }

        var environment = ProcessInfo.processInfo.environment
        environment["SHELL"] = shell.path

        let executable = Self.builtExecutable()
        let answer = try ChildProcess.run(
            executable.path,
            [],
            environment: environment,
            timeout: 10,
            readsNoInput: true
        )

        #expect(answer.exitCode == CommandLineApplication.ExitCode.didNotParse.rawValue)
        #expect(FileManager.default.fileExists(atPath: marker.path) == false)
    }

    /// This package's root, read from where this source file sits rather than
    /// from the test process's own path, which a test runner may rewrite.
    private static let packageRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    /// The `threatmodeller-cli` product this package's own build wrote, under
    /// whichever target triple this machine built for.
    private static func builtExecutable() -> URL {
        let buildDirectory = packageRoot.appendingPathComponent(".build")
        let triples = ((try? FileManager.default.contentsOfDirectory(atPath: buildDirectory.path)) ?? [])
            .filter { $0.contains(Self.platformMarker) }
        for triple in triples {
            let candidate = buildDirectory
                .appendingPathComponent(triple)
                .appendingPathComponent("debug")
                .appendingPathComponent("threatmodeller-cli")
            if FileManager.default.isExecutableFile(atPath: candidate.path) { return candidate }
        }
        return buildDirectory.appendingPathComponent("debug").appendingPathComponent("threatmodeller-cli")
    }

    /// The word this machine's own build triple holds, so a `.build`
    /// directory another platform's job wrote beside it is skipped.
    private static var platformMarker: String {
        #if os(macOS)
        return "apple"
        #else
        return "linux"
        #endif
    }
}
