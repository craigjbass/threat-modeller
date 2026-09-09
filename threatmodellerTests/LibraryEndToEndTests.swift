import Foundation
import Testing
import ThreatModelKit
@testable import threatmodeller

/// The Libraries sheet's path, end to end: the real composition root, the real
/// file system, the real `git`, and a repository this test builds.
///
/// It reaches no server. `git init` in a temporary directory and a clone by
/// path run the real tool, which is what proves a user's own repository works.
@MainActor
struct LibraryEndToEndTests {
    private let library = """
    library "acme" {
      name = "Acme Platform"

      technology "cribl-stream" {
        name     = "Cribl Stream"
        category = "monitoring"
        threats  = ["pipeline-tamper"]
      }

      threat "pipeline-tamper" {
        name     = "Pipeline tampering"
        severity = "high"

        control "Sign pipeline configurations"
      }
    }

    """

    private func git(_ arguments: [String], in directory: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["git"] + arguments
        process.currentDirectoryURL = directory
        process.standardOutput = Pipe()
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
    }

    /// A repository holding one library at `v1.0.0`, and a project that names
    /// its technology.
    private func aWorld() throws -> (repository: URL, project: URL) {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("library-end-to-end-\(UUID().uuidString)")
        let repository = root.appendingPathComponent("elements")
        let project = root.appendingPathComponent("project")
        let threatmodel = project.appendingPathComponent("threatmodel")
        try FileManager.default.createDirectory(at: repository, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: threatmodel, withIntermediateDirectories: true)

        try library.write(
            to: repository.appendingPathComponent("acme.lib"),
            atomically: true,
            encoding: .utf8
        )
        try git(["init", "--initial-branch=main"], in: repository)
        try git(["add", "."], in: repository)
        try git(
            ["-c", "user.email=a@b.c", "-c", "user.name=A", "-c", "commit.gpgsign=false",
             "commit", "-m", "one"],
            in: repository
        )
        try git(["tag", "v1.0.0"], in: repository)

        try """
        system "Payments" {
          component "ingest" { technology = "acme-cribl-stream" }
        }
        """.write(
            to: threatmodel.appendingPathComponent("payments.arch"),
            atomically: true,
            encoding: .utf8
        )
        return (repository, project)
    }

    @Test func addsARealRepositoryAndRaisesItsThreat() async throws {
        let world = try aWorld()
        defer {
            try? FileManager.default.removeItem(
                at: world.project.deletingLastPathComponent()
            )
        }
        let useCases = try Dependencies()
        let project = ProjectSession(useCases: useCases, defaults: aTestDefaults())
        let libraries = LibrarySession(
            useCases: useCases,
            root: world.project.path,
            onChange: { project.reloadFromDisk() }
        )

        await libraries.add(repository: world.repository.path, tag: "v1.0.0")

        #expect(libraries.errorMessage == nil)
        let row = try #require(libraries.libraries.first)
        #expect(row.label == "acme")
        #expect(row.name == "Acme Platform")
        #expect(row.tag == "v1.0.0")
        #expect(row.matchesLock)

        // The files are on disk, and a second application would read them.
        let vendored = world.project
            .appendingPathComponent("threatmodel/library/acme.lib")
        #expect(FileManager.default.fileExists(atPath: vendored.path))
        #expect(
            FileManager.default.fileExists(
                atPath: world.project
                    .appendingPathComponent("threatmodel/library/library.lock.json").path
            )
        )

        // The project now raises the threat only the library defines.
        project.open(root: world.project.path)
        #expect(project.errorMessage == nil)
        let threats = try #require(project.model?.threats)
        #expect(threats.contains { $0.threatId == "acme-pipeline-tamper" })
        #expect(project.model?.palette.contains { $0.id == "acme" } == true)
    }

    @Test func saysWhatGitSaidWhenTheRepositoryIsNotThere() async throws {
        let world = try aWorld()
        defer {
            try? FileManager.default.removeItem(
                at: world.project.deletingLastPathComponent()
            )
        }
        let libraries = LibrarySession(
            useCases: try Dependencies(),
            root: world.project.path,
            onChange: {}
        )

        await libraries.add(repository: "/no/such/repository", tag: "v1.0.0")

        #expect(libraries.libraries.isEmpty)
        // `git`'s own message, which is what tells a user what is wrong.
        #expect(libraries.errorMessage?.contains("does not exist") == true)
    }

    @Test func removesARealLibraryOnlyWhenTheUserSaysSoTwice() async throws {
        let world = try aWorld()
        defer {
            try? FileManager.default.removeItem(
                at: world.project.deletingLastPathComponent()
            )
        }
        let libraries = LibrarySession(
            useCases: try Dependencies(),
            root: world.project.path,
            onChange: {}
        )
        await libraries.add(repository: world.repository.path, tag: "v1.0.0")

        libraries.remove(label: "acme", isForced: false)
        #expect(libraries.removalInUse == ["payments"])
        #expect(libraries.libraries.count == 1)

        libraries.remove(label: "acme", isForced: true)

        #expect(libraries.libraries.isEmpty)
        #expect(
            FileManager.default.fileExists(
                atPath: world.project
                    .appendingPathComponent("threatmodel/library/acme.lib").path
            ) == false
        )
    }
}
