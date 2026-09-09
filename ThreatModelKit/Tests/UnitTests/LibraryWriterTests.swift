import Testing
import ThreatModelKit
@testable import ArchitectureDSL

@Suite("Writing the library language")
struct LibraryWriterTests {
    private let text = """
    library "acme" {
      name      = "Acme Platform"
      catalogue = "v1.0.1"

      technology "cribl-stream" {
        name     = "Cribl Stream"
        category = "monitoring"
        threats  = ["pipeline-tamper"]
        encrypts = true
      }

      threat "pipeline-tamper" {
        name     = "Pipeline tampering"
        severity = "high"
        stride   = ["tampering"]

        mitre "T1565" {
          name   = "Data Manipulation"
          tactic = "impact"
        }

        control "Sign pipeline configurations"
      }
    }

    """

    private func read(_ text: String) -> LibraryRead {
        let scanned = Lexer(text).scan()
        var parser = LibraryParser(tokens: scanned.tokens, faults: scanned.faults)
        return parser.parse()
    }

    @Test func writesACanonicalFileItCanReadBack() throws {
        let source = try #require(read(text).source)

        #expect(LibraryWriter().write(source) == text)
    }

    @Test func parseWriteParseGivesTheSameTree() throws {
        let once = try #require(read(text).source)

        let twice = try #require(read(LibraryWriter().write(once)).source)

        #expect(once == twice)
    }

    @Test func writesTheSmallestLibraryItCanRead() throws {
        let smallest = "library \"acme\" {\n}\n"
        let source = try #require(read(smallest).source)

        #expect(LibraryWriter().write(source) == smallest)
    }
}
