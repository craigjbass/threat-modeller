import Foundation
import Testing
@testable import threatmodeller

/// Installing the command, and saying plainly what state it is in.
///
/// Every test runs over a temporary directory that stands for the user's home
/// and for the application bundle, so no test writes into either.
@MainActor
struct CommandLineToolTests {
    /// A world: an application bundle carrying the helper, and a home.
    private struct World {
        let root: URL
        let app: URL
        let home: URL
        var helper: URL { app.appendingPathComponent("Contents/Resources/threatmodeller-cli/threatmodeller") }
        var installed: URL { home.appendingPathComponent(".local/bin/threatmodeller") }
    }

    private func aWorld(carryingTheHelper: Bool = true, path: String = "/usr/bin:/bin") throws -> (World, CommandLineTool) {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("command-line-tool-\(UUID().uuidString)")
        let app = root.appendingPathComponent("threatmodeller.app")
        let home = root.appendingPathComponent("home")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)

        let helpers = app.appendingPathComponent("Contents/Resources/threatmodeller-cli")
        try FileManager.default.createDirectory(at: helpers, withIntermediateDirectories: true)
        if carryingTheHelper {
            try "binary".write(
                to: helpers.appendingPathComponent("threatmodeller"),
                atomically: true,
                encoding: .utf8
            )
        }

        let world = World(root: root, app: app, home: home)
        return (world, CommandLineTool(bundle: app, home: home, path: path))
    }

    private func remove(_ world: World) {
        try? FileManager.default.removeItem(at: world.root)
    }

    @Test func saysTheCommandIsNotInstalledYet() throws {
        let (world, tool) = try aWorld()
        defer { remove(world) }

        #expect(tool.status() == .notInstalled(target: world.installed.path, isOnPath: false))
    }

    @Test func saysTheDirectoryIsOnThePathWhenItIs() throws {
        let (world, tool) = try aWorld(path: "/usr/bin")
        defer { remove(world) }
        let onPath = CommandLineTool(
            bundle: world.app,
            home: world.home,
            path: "/usr/bin:\(world.home.path)/.local/bin"
        )

        #expect(onPath.status() == .notInstalled(target: world.installed.path, isOnPath: true))
        #expect(tool.status() == .notInstalled(target: world.installed.path, isOnPath: false))
    }

    @Test func saysSoWhenThisBuildCarriesNoCommand() throws {
        let (world, tool) = try aWorld(carryingTheHelper: false)
        defer { remove(world) }

        #expect(tool.status() == .notInThisBuild)
    }

    @Test func writesALinkIntoTheUsersOwnDirectory() throws {
        let (world, tool) = try aWorld()
        defer { remove(world) }

        #expect(tool.install() == .installed(at: world.installed.path))

        let destination = try FileManager.default.destinationOfSymbolicLink(
            atPath: world.installed.path
        )
        #expect(destination == world.helper.path)
        #expect(tool.status() == .installed(at: world.installed.path, isCurrent: true, isOnPath: false))
    }

    @Test func makesTheDirectoryWhenItIsNotThere() throws {
        let (world, tool) = try aWorld()
        defer { remove(world) }
        #expect(
            FileManager.default.fileExists(
                atPath: world.home.appendingPathComponent(".local/bin").path
            ) == false
        )

        _ = tool.install()

        #expect(
            FileManager.default.fileExists(
                atPath: world.home.appendingPathComponent(".local/bin").path
            )
        )
    }

    @Test func writesOverALinkThatIsAlreadyThere() throws {
        let (world, tool) = try aWorld()
        defer { remove(world) }
        try FileManager.default.createDirectory(
            at: world.installed.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try FileManager.default.createSymbolicLink(
            atPath: world.installed.path,
            withDestinationPath: "/somewhere/old/threatmodeller"
        )

        #expect(tool.install() == .installed(at: world.installed.path))

        #expect(
            try FileManager.default.destinationOfSymbolicLink(atPath: world.installed.path)
                == world.helper.path
        )
    }

    @Test func refusesToWriteOverAFileItDidNotWrite() throws {
        let (world, tool) = try aWorld()
        defer { remove(world) }
        try FileManager.default.createDirectory(
            at: world.installed.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try "someone else's tool".write(to: world.installed, atomically: true, encoding: .utf8)

        guard case .refused(let reason) = tool.install() else {
            Issue.record("it wrote over a file it did not write")
            return
        }

        #expect(reason.contains(world.installed.path))
        #expect(try String(contentsOf: world.installed, encoding: .utf8) == "someone else's tool")
    }

    @Test func saysWhenTheLinkPointsAtAnotherCopyOfTheApplication() throws {
        let (world, tool) = try aWorld()
        defer { remove(world) }
        try FileManager.default.createDirectory(
            at: world.installed.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try FileManager.default.createSymbolicLink(
            atPath: world.installed.path,
            withDestinationPath: "/Applications/threatmodeller.app/Contents/Resources/threatmodeller-cli/threatmodeller"
        )

        #expect(
            tool.status()
                == .installed(
                    at: world.installed.path,
                    isCurrent: false,
                    isOnPath: false
                )
        )
    }

    @Test func removesTheLinkItWrote() throws {
        let (world, tool) = try aWorld()
        defer { remove(world) }
        _ = tool.install()

        #expect(tool.uninstall() == .removed)

        #expect(FileManager.default.fileExists(atPath: world.installed.path) == false)
        #expect(tool.status() == .notInstalled(target: world.installed.path, isOnPath: false))
    }

    @Test func refusesToRemoveAFileItDidNotWrite() throws {
        let (world, tool) = try aWorld()
        defer { remove(world) }
        try FileManager.default.createDirectory(
            at: world.installed.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try "someone else's tool".write(to: world.installed, atomically: true, encoding: .utf8)

        guard case .refused = tool.uninstall() else {
            Issue.record("it removed a file it did not write")
            return
        }

        #expect(FileManager.default.fileExists(atPath: world.installed.path))
    }

    @Test func saysTheLineToAddToTheShellProfile() throws {
        let (world, tool) = try aWorld()
        defer { remove(world) }

        #expect(
            tool.pathLine
                == "export PATH=\"$HOME/.local/bin:$PATH\""
        )
    }
}
