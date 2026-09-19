import FileGateways
import Foundation
import Testing
import TestSupport
import ThreatModelKit

/// The `PATH` a child process searches: this process's own entries, then the
/// entries the person's login shell adds.
///
/// A window started from the Finder inherits launchd's `PATH`, which holds no
/// `~/go/bin`, `/opt/homebrew/bin` or `~/.local/bin`. The shell the person
/// types into does. Each test writes its own shell script, so no test reads
/// this machine's rc files.
@Suite("The PATH the login shell holds")
struct ShellPathTests {
    private func aShell(printing script: String) throws -> String {
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("shell-\(UUID().uuidString).sh")
        try ToolScript.write("#!/bin/sh\n\(script)\n", to: file.path)
        return file.path
    }

    @Test func addsTheEntriesTheShellPrintsAfterTheProcessEntries() throws {
        let shell = try aShell(printing: "echo \"\(ShellPath.marker)/fake/go/bin:/opt/fake/bin\(ShellPath.marker)\"")

        let path = ShellPath.read(shell: shell, processPath: "/usr/bin:/bin")

        #expect(path == "/usr/bin:/bin:/fake/go/bin:/opt/fake/bin")
    }

    @Test func anEntryTheProcessAlreadyHoldsIsNotAddedAgain() throws {
        let shell = try aShell(printing: "echo \"\(ShellPath.marker)/bin:/fake/bin:/usr/bin\(ShellPath.marker)\"")

        let path = ShellPath.read(shell: shell, processPath: "/usr/bin:/bin")

        #expect(path == "/usr/bin:/bin:/fake/bin")
    }

    @Test func whatTheRcFilesPrintAroundTheMarkerIsIgnored() throws {
        let shell = try aShell(printing: """
        echo "Welcome to the machine"
        echo "\(ShellPath.marker)/fake/bin\(ShellPath.marker)"
        echo "bye"
        """)

        let path = ShellPath.read(shell: shell, processPath: "/usr/bin")

        #expect(path == "/usr/bin:/fake/bin")
    }

    @Test func aShellThatIsNotThereLeavesTheProcessPath() {
        let path = ShellPath.read(shell: "/no/such/shell", processPath: "/usr/bin:/bin")

        #expect(path == "/usr/bin:/bin")
    }

    @Test func aShellThatPrintsNoMarkerLeavesTheProcessPath() throws {
        let shell = try aShell(printing: "echo /fake/bin")

        let path = ShellPath.read(shell: shell, processPath: "/usr/bin:/bin")

        #expect(path == "/usr/bin:/bin")
    }

    @Test func aShellThatWaitsIsKilledAndLeavesTheProcessPath() throws {
        let shell = try aShell(printing: "sleep 30")

        let path = ShellPath.read(shell: shell, processPath: "/usr/bin:/bin", timeout: 0.2)

        #expect(path == "/usr/bin:/bin")
    }

    @Test func theShellIsAskedAsAnInteractiveLoginShellAndRunsTheCommandItIsGiven() throws {
        // `~/.zshrc` runs for an interactive shell only, and that is the file
        // most people set PATH in. This shell runs the command the way a real
        // one does, so the command's own expansion of PATH is what is read.
        let shell = try aShell(printing: """
        [ "$1" = "-ilc" ] || exit 1
        PATH=/fake/go/bin
        eval "$2"
        """)

        let path = ShellPath.read(shell: shell, processPath: "/usr/bin")

        #expect(path == "/usr/bin:/fake/go/bin")
    }

    @Test func theEnvironmentForAChildHoldsThatPath() {
        let environment = ShellPath.environment(path: "/fake/bin", of: ["HOME": "/Users/a", "PATH": "/usr/bin"])

        #expect(environment == ["HOME": "/Users/a", "PATH": "/fake/bin"])
    }
}
