@testable import ArchitectureDSL
import FileGateways
import Testing
import ThreatModelKit
import TestSupport

@Suite("The pictures a team keeps beside the diagram")
struct SystemDiagramTests {
    private let app = TestDependencies()
    private let architecture = HclArchitectureSource()

    private let payments = """
    system "Payments" {
      diagram "The login sequence" {
        kind = "mermaid"
        text = <<EOT
    sequenceDiagram
      Customer->>API: signs in
      API->>Database: reads the account
    EOT
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    @Test func aSystemKeepsAPicture() throws {
        let source = try #require(architecture.read(payments).source)

        #expect(source.diagrams.count == 1)
        #expect(source.diagrams[0].label == "The login sequence")
        #expect(source.diagrams[0].kind == "mermaid")
        #expect(source.diagrams[0].text.contains("sequenceDiagram"))
        #expect(source.diagrams[0].text.contains("Customer->>API: signs in"))
    }

    /// The heredoc is kept byte for byte, so the picture reads back the way a
    /// person wrote it.
    @Test func theHeredocKeepsEveryLine() throws {
        let source = try #require(architecture.read(payments).source)

        #expect(
            source.diagrams[0].text == """
            sequenceDiagram
              Customer->>API: signs in
              API->>Database: reads the account

            """
        )
    }

    @Test func aDiagramWithNoTextIsRefused() {
        let text = """
        system "Payments" {
          diagram "Empty" {
            kind = "mermaid"
            text = <<EOT
        EOT
          }
        }

        """
        let read = architecture.read(text)

        #expect(read.diagnostics.contains { $0.message.contains("has no text") })
    }

    @Test func aHeredocWithNoClosingLineIsRefused() {
        let text = """
        system "Payments" {
          diagram "Open" {
            text = <<EOT
        sequenceDiagram
          }
        }
        """
        let read = architecture.read(text)

        #expect(read.diagnostics.contains { $0.message.contains("no closing") })
    }

    @Test func aKindOutsideMermaidIsRefused() {
        let text = """
        system "Payments" {
          diagram "The login sequence" {
            kind = "plantuml"
            text = <<EOT
        one
        EOT
          }
        }

        """
        let read = architecture.read(text)

        #expect(read.diagnostics.contains { $0.message.contains("plantuml") })
    }

    @Test func aRoundTripWritesTheFileItRead() throws {
        let source = try #require(architecture.read(payments).source)

        let written = architecture.write(source)
        let again = try #require(architecture.read(written).source)

        #expect(again.diagrams == source.diagrams)
        #expect(architecture.write(again) == written)
    }

    @Test func theReportWritesEachDiagramAsAFencedBlock() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("## Diagrams"))
        #expect(markdown.contains("### The login sequence"))
        #expect(markdown.contains("```mermaid"))
        #expect(markdown.contains("sequenceDiagram"))
    }

    /// The diagrams read after the model inventory.
    @Test func theDiagramsComeAfterTheModelInventory() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        let inventory = try #require(markdown.range(of: "## Appendix B"))
        let diagrams = try #require(markdown.range(of: "## Diagrams"))
        #expect(inventory.lowerBound < diagrams.lowerBound)
    }

    @Test func thePageShowsTheSourceOfADiagramItCannotDraw() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
        let html = MarkdownToHtml.html(of: markdown, title: "Payments")

        #expect(html.contains("<pre class=\"mermaid\">"))
        #expect(html.contains("sequenceDiagram"))
        #expect(html.contains("Customer-&gt;&gt;API: signs in"))
    }

    @Test func aSystemWithNoDiagramWritesNoSection() {
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  component "api" {
                    technology = "aws-ec2"
                  }
                }

                """
            )
        )
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("## Diagrams") == false)
    }

    @Test func aWrittenSourceHoldsNoVerbatimMark() throws {
        let source = try #require(architecture.read(payments).source)

        let written = architecture.write(source)

        #expect(written.contains(ArchitectureWriter.verbatimMark) == false)
    }

    @Test func aWrittenPartHoldsNoVerbatimMark() throws {
        let source = try #require(architecture.read(payments).source)

        let written = architecture.writePart(source)

        #expect(written.contains(ArchitectureWriter.verbatimMark) == false)
    }

    @Test func aDiagramBodyStartingWithASpaceKeepsTheSpaceAndWritesNoMark() throws {
        let text = """
        system "Payments" {
          diagram "The login sequence" {
            kind = "mermaid"
            text = <<EOT
          indented body
        EOT
          }
        }

        """
        let source = try #require(architecture.read(text).source)

        #expect(source.diagrams[0].text.hasPrefix("  indented body"))

        let written = architecture.write(source)

        #expect(written.contains(ArchitectureWriter.verbatimMark) == false)
    }

    @Test func aSavedModelKeepsTheDiagrams() throws {
        let model = ThreatModel(
            name: "Payments",
            diagrams: [
                SystemDiagram(label: "The login sequence", text: "sequenceDiagram\n")
            ]
        )
        let codec = ThreatModelCodec()
        let read = try codec.decode(try codec.encode(model))

        #expect(read.diagrams == model.diagrams)
    }
}
