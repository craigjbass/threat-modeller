import CommandLineApplication
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// The window runs `SplitSystem` where the executable runs `split` inline.
/// The two move the same files to the same places for the same project.
@Suite("Moving a flat system into a directory")
struct SplitSystemUseCaseTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func run(_ project: InMemoryProject, _ words: String...) -> (code: Int32, lines: [String]) {
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller"] + words, output: { lines.append($0) })
        return (code, lines)
    }

    @Test func movesTheArchitectureAndControlsFilesIntoADirectory() {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.project.put(
            "controls for \"Payments\" {\n}\n", at: "/work/threatmodel/payments.controls"
        )

        let response = useCases.splitSystem().execute(
            SplitSystemRequest(root: "/work", systemName: "payments")
        )

        #expect(response == .split)
        #expect(useCases.project.text(at: "/work/threatmodel/payments/arch/payments.arch") != nil)
        #expect(
            useCases.project.text(at: "/work/threatmodel/payments/controls/payments.controls") != nil
        )
        #expect(useCases.project.text(at: "/work/threatmodel/payments.arch") == nil)
        #expect(useCases.project.text(at: "/work/threatmodel/payments.controls") == nil)
    }

    @Test func refusesASystemThatIsAlreadyADirectory() {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments/arch/payments.arch")

        let response = useCases.splitSystem().execute(
            SplitSystemRequest(root: "/work", systemName: "payments")
        )

        #expect(response == .alreadySplit)
    }

    @Test func refusesASystemTheProjectDoesNotHold() {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")

        let response = useCases.splitSystem().execute(
            SplitSystemRequest(root: "/work", systemName: "ledger")
        )

        #expect(response == .noSuchSystem)
    }

    /// The window's use case and the executable's verb move the same
    /// project's files to the same places, holding the same bytes.
    @Test func movesTheSameFilesToTheSamePlacesTheVerbMoves() throws {
        let verbProject = InMemoryProject(root: "/work")
        verbProject.put(payments, at: "/work/threatmodel/payments.arch")
        let verbResult = run(verbProject, "split", "payments", "/work")
        #expect(verbResult.code == 0)

        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let response = useCases.splitSystem().execute(
            SplitSystemRequest(root: "/work", systemName: "payments")
        )
        #expect(response == .split)

        let fromTheVerb = try #require(
            verbProject.text(at: "/work/threatmodel/payments/arch/payments.arch")
        )
        let fromTheWindow = try #require(
            useCases.project.text(at: "/work/threatmodel/payments/arch/payments.arch")
        )
        #expect(fromTheWindow == fromTheVerb)
        #expect(verbProject.text(at: "/work/threatmodel/payments.arch") == nil)
        #expect(useCases.project.text(at: "/work/threatmodel/payments.arch") == nil)
    }

    /// A split system reads and writes the same way after a split: the moved
    /// files still compile.
    @Test func aSplitSystemStillCompilesAfterASplit() {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")

        _ = useCases.splitSystem().execute(SplitSystemRequest(root: "/work", systemName: "payments"))

        let result = run(useCases.project, "compile", "/work")
        #expect(result.code == 0)
        #expect(
            useCases.project.text(at: "/work/threatmodel/payments/controls/payments.controls") != nil
        )
    }
}
