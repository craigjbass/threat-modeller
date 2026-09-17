import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Reading and writing a system's own diagram block in the window, end to
/// end: the list the assumptions panel draws, the `diagram` block the save
/// writes, and what the parser reads back from it.
@MainActor
@Suite("A system's own diagram in the window")
struct SystemDiagramEditorFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private let withDiagram = """
    system "Payments" {
      diagram "The login sequence" {
        kind = "mermaid"
        text = <<EOT
    sequenceDiagram
      Customer->>API: signs in
    EOT
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject(_ text: String? = nil) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(text ?? payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func architecture(_ useCases: TestDependencies) -> String? {
        useCases.project.text(at: "/work/threatmodel/payments.arch")
    }

    // MARK: the list

    @Test func listsEveryDiagramTheFileStates() async throws {
        let (session, _) = await aProject(withDiagram)
        let model = try #require(session.model)

        let diagram = try #require(model.canvas.diagrams.first)
        #expect(diagram.label == "The login sequence")
        #expect(diagram.text.contains("sequenceDiagram"))
        #expect(diagram.text.contains("Customer->>API: signs in"))
    }

    // MARK: writing a block

    @Test func writesADiagramIntoTheFile() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setSystemDiagram(
            label: "The login sequence",
            text: "sequenceDiagram\n  Customer->>API: signs in"
        )
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("diagram \"The login sequence\""))
        #expect(written.contains("kind = \"mermaid\""))
        #expect(written.contains("<<EOT"))
        #expect(written.contains("sequenceDiagram"))
        #expect(written.contains("Customer->>API: signs in"))
    }

    // MARK: the round trip

    /// A block written in the window and one written by hand produce the
    /// same bytes, so a person can hand-edit a file the window later saves.
    @Test func aBlockWrittenInTheWindowMatchesOneWrittenByHandByteForByte() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setSystemDiagram(
            label: "The login sequence",
            text: "sequenceDiagram\n  Customer->>API: signs in"
        )
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(architecture(useCases) == withDiagram)
    }

    @Test func writesTheBlockAndLeavesEveryOtherBlockWhereItWas() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        // A save with nothing changed, so the two texts differ by the
        // diagram's own lines alone and by nothing the writer normalises.
        await session.save()
        let before = try #require(architecture(useCases))

        model.setSystemDiagram(
            label: "The login sequence",
            text: "sequenceDiagram\n  Customer->>API: signs in"
        )
        await session.save()
        let after = try #require(architecture(useCases))

        #expect(model.errorMessage == nil)
        #expect(after != before)
        #expect(
            Self.holdsEveryLine(of: before, inOrder: after),
            "the write moved or dropped a line the file already held"
        )

        model.removeSystemDiagram(label: "The login sequence")
        await session.save()

        #expect(architecture(useCases) == before)
    }

    /// True when every line of `before` is in `after`, in the same order. A
    /// new block adds lines; it must change none of the lines around it.
    private static func holdsEveryLine(of before: String, inOrder after: String) -> Bool {
        var wanted = before.split(separator: "\n", omittingEmptySubsequences: true)[...]
        for line in after.split(separator: "\n", omittingEmptySubsequences: true) {
            if wanted.first == line { wanted = wanted.dropFirst() }
        }
        return wanted.isEmpty
    }

    @Test func changesADiagramThatIsAlreadyThere() async throws {
        let (session, useCases) = await aProject(withDiagram)
        let model = try #require(session.model)

        model.setSystemDiagram(
            label: "The login sequence",
            text: "sequenceDiagram\n  Customer->>API: signs out"
        )
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(model.canvas.diagrams.count == 1)
        let written = try #require(architecture(useCases))
        #expect(written.contains("signs out"))
        #expect(written.contains("signs in") == false)
    }

    @Test func takesADiagramOffTheFile() async throws {
        let (session, useCases) = await aProject(withDiagram)
        let model = try #require(session.model)

        model.removeSystemDiagram(label: "The login sequence")
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("diagram \"The login sequence\"") == false)
    }

    @Test func theParserReadsTheBlockBackWithTheSameFields() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setSystemDiagram(
            label: "The login sequence",
            text: "sequenceDiagram\n  Customer->>API: signs in"
        )
        await session.save()

        let text = try #require(architecture(useCases))
        let source = try #require(HclArchitectureSource().read(text).source)
        let diagram = try #require(source.diagrams.first)
        #expect(diagram.label == "The login sequence")
        #expect(diagram.kind == "mermaid")
        #expect(diagram.text.contains("sequenceDiagram"))
        #expect(diagram.text.contains("Customer->>API: signs in"))
    }

    // MARK: the kind

    /// #161: the window stated no `kind` on a `diagram` block, so a person
    /// could not write a D2 picture even though the parser reads one.
    @Test func writesTheD2KindIntoTheFile() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setSystemDiagram(label: "Deployment", kind: "d2", text: "a -> b")
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("kind = \"d2\""))
    }

    @Test func theParserReadsTheD2KindBackWithTheSameValue() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setSystemDiagram(label: "Deployment", kind: "d2", text: "a -> b")
        await session.save()

        let text = try #require(architecture(useCases))
        let source = try #require(HclArchitectureSource().read(text).source)
        let diagram = try #require(source.diagrams.first)
        #expect(diagram.kind == "d2")
    }

    @Test func theSheetShowsTheKindPicker() async throws {
        let (session, _) = await aProject(withDiagram)
        let model = try #require(session.model)

        #expect(model.canvas.diagrams.first?.kind == "mermaid")
    }

    // MARK: the report

    @Test func aReportBuiltAfterTheWriteShowsTheDiagramUnderItsLabel() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setSystemDiagram(
            label: "The login sequence",
            text: "sequenceDiagram\n  Customer->>API: signs in"
        )
        await session.save()

        let markdown = useCases.exportModelAsMarkdown()
            .execute(ExportModelAsMarkdownRequest()).markdown
        #expect(markdown.contains("### The login sequence"))
        #expect(markdown.contains("```mermaid"))
        #expect(markdown.contains("sequenceDiagram"))
    }

    // MARK: the sheet

    /// #145: the diagram editor left the architecture sidebar for the
    /// Diagrams sheet the System menu opens, so the drawing test draws the
    /// sheet.
    @Test func theDiagramsSheetDraws() async throws {
        let (session, _) = await aProject(withDiagram)
        let model = try #require(session.model)

        let renderer = ImageRenderer(
            content: DiagramsSheet(session: model, dismiss: {}).frame(width: 760, height: 520)
        )
        renderer.scale = 1

        #expect(renderer.cgImage != nil)
    }
}
