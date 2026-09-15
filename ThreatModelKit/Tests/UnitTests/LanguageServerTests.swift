@testable import CommandLineApplication
import Foundation
import Testing
import ThreatModelKit
import TestSupport

@Suite("Speaking the Language Server Protocol")
struct LanguageServerTests {
    private let project = InMemoryProject(root: "/work")

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "db" {
        technology = "aws-rds"
        data       = "restricted"
      }

      flow api -> db
    }

    """

    private let uri = "file:///work/threatmodel/payments.arch"

    private func server() -> LanguageServer {
        LanguageServer(projects: project, catalogue: { CatalogueFixture.catalogue() })
    }

    /// A fake client: it writes one message and reads what came back.
    private func ask(_ server: LanguageServer, _ message: [String: Any]) -> [[String: Any]] {
        let data = try? JSONSerialization.data(withJSONObject: message)
        return server.answer(to: String(decoding: data ?? Data(), as: UTF8.self))
            .compactMap { text in
                guard let bytes = text.data(using: .utf8) else { return nil }
                return try? JSONSerialization.jsonObject(with: bytes) as? [String: Any]
            }
    }

    private func opened(_ text: String? = nil, at uri: String? = nil) -> LanguageServer {
        let server = server()
        _ = ask(server, [
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": [
                "textDocument": ["uri": uri ?? self.uri, "text": text ?? payments]
            ]
        ])
        return server
    }

    private func result(_ answers: [[String: Any]]) -> Any? {
        answers.first { $0["result"] != nil }?["result"]
    }

    // MARK: the protocol

    @Test func statesWhatItCanDo() throws {
        let answers = ask(server(), ["jsonrpc": "2.0", "id": 1, "method": "initialize", "params": [:]])
        let capabilities = try #require(
            (result(answers) as? [String: Any])?["capabilities"] as? [String: Any]
        )

        #expect(capabilities["textDocumentSync"] as? Int == 1)
        #expect(capabilities["hoverProvider"] as? Bool == true)
        #expect(capabilities["definitionProvider"] as? Bool == true)
        #expect(capabilities["documentFormattingProvider"] as? Bool == true)
        #expect(capabilities["completionProvider"] != nil)
    }

    // MARK: diagnostics

    @Test func publishesTheParsersOwnDiagnostics() throws {
        let broken = """
        system "Payments" {
          zone "app" {
            kind = "secret"
          }
        }

        """
        let answers = ask(server(), [
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": ["textDocument": ["uri": uri, "text": broken]]
        ])

        let published = try #require(answers.first)
        #expect(published["method"] as? String == "textDocument/publishDiagnostics")
        let parameters = try #require(published["params"] as? [String: Any])
        let diagnostics = try #require(parameters["diagnostics"] as? [[String: Any]])
        #expect(diagnostics.isEmpty == false)
        let first = try #require(diagnostics.first)
        #expect((first["message"] as? String)?.contains("secret") == true)
        #expect(first["severity"] as? Int == 1)
        // The parser counts from one and the protocol counts from zero.
        let start = try #require(
            (first["range"] as? [String: Any])?["start"] as? [String: Any]
        )
        #expect(start["line"] as? Int == 2)
    }

    @Test func publishesAgainOnEveryChange() throws {
        let server = opened()
        let answers = ask(server, [
            "jsonrpc": "2.0",
            "method": "textDocument/didChange",
            "params": [
                "textDocument": ["uri": uri],
                "contentChanges": [["text": "system \"Payments\" {\n  zone \"z\" { kind = \"secret\" }\n}\n"]]
            ]
        ])
        let diagnostics = try #require(
            (answers.first?["params"] as? [String: Any])?["diagnostics"] as? [[String: Any]]
        )

        #expect(diagnostics.isEmpty == false)
    }

    @Test func publishesAnEmptyListForAFileThatParses() throws {
        let answers = ask(server(), [
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": ["textDocument": ["uri": uri, "text": payments]]
        ])
        let diagnostics = try #require(
            (answers.first?["params"] as? [String: Any])?["diagnostics"] as? [[String: Any]]
        )

        #expect(diagnostics.isEmpty)
    }

    // MARK: completion

    private func completions(
        _ server: LanguageServer,
        line: Int,
        character: Int,
        at uri: String? = nil
    ) -> [String] {
        let answers = ask(server, [
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/completion",
            "params": [
                "textDocument": ["uri": uri ?? self.uri],
                "position": ["line": line, "character": character]
            ]
        ])
        let items = (result(answers) as? [String: Any])?["items"] as? [[String: Any]] ?? []
        return items.compactMap { $0["label"] as? String }
    }

    @Test func completesATechnologyId() {
        let labels = completions(opened(), line: 2, character: 16)

        #expect(labels.contains("aws-ec2"))
        #expect(labels.contains("aws-rds"))
    }

    @Test func completesAComponentIdInAFlow() {
        let labels = completions(opened(), line: 11, character: 7)

        #expect(labels.contains("api"))
        #expect(labels.contains("db"))
    }

    @Test func completesTheAttributesOfTheBlockTheCursorSitsIn() {
        let labels = completions(opened(), line: 3, character: 4)

        #expect(labels.contains("technology"))
        #expect(labels.contains("runs_as"))
        #expect(labels.contains("holds"))
    }

    @Test func completesAThreatIdInAControlsFile() {
        let controls = """
        controls for "Payments" {
          threat "" on component "api" {
          }
        }

        """
        let server = opened(controls, at: "file:///work/threatmodel/payments.controls")
        let labels = completions(
            server,
            line: 1,
            character: 10,
            at: "file:///work/threatmodel/payments.controls"
        )

        #expect(labels.isEmpty == false)
        #expect(labels.contains("credential-theft"))
    }

    @Test func completesTheControlsOfTheThreatAbove() throws {
        let controls = """
        controls for "Payments" {
          threat "credential-theft" on component "api" {
            control ""
          }
        }

        """
        let uri = "file:///work/threatmodel/payments.controls"
        let labels = completions(opened(controls, at: uri), line: 2, character: 12, at: uri)

        #expect(labels.isEmpty == false)
    }

    @Test func completesAZoneName() {
        let zoned = """
        system "Payments" {
          zone "app" {
            kind = "private"
          }

          component "api" {
            technology = "aws-ec2"
          }
        }

        """
        let labels = completions(opened(zoned), line: 1, character: 8)

        #expect(labels.contains("app"))
    }

    // MARK: hover

    private func hovered(_ server: LanguageServer, line: Int, character: Int) -> String {
        let answers = ask(server, [
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/hover",
            "params": [
                "textDocument": ["uri": uri],
                "position": ["line": line, "character": character]
            ]
        ])
        let contents = (result(answers) as? [String: Any])?["contents"] as? [String: Any]
        return contents?["value"] as? String ?? ""
    }

    @Test func hoversOnATechnologyWithItsDescriptionAndItsThreats() {
        let said = hovered(opened(), line: 2, character: 20)

        #expect(said.contains("aws-ec2"))
        #expect(said.contains("Raises "))
        #expect(said.contains("credential-theft"))
    }

    @Test func hoversOnAThreatStanzaWithItsScoreAndItsLevel() {
        let controls = """
        controls for "Payments" {
          threat "credential-theft" on component "api" {
            severity = "Critical"
            score    = 12
          }
        }

        """
        let uri = "file:///work/threatmodel/payments.controls"
        let server = opened(controls, at: uri)
        let answers = ask(server, [
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/hover",
            "params": [
                "textDocument": ["uri": uri],
                "position": ["line": 1, "character": 12]
            ]
        ])
        let said = ((result(answers) as? [String: Any])?["contents"] as? [String: Any])?["value"]
            as? String ?? ""

        #expect(said.contains("score 12"))
        #expect(said.contains("level Critical"))
    }

    @Test func hoversOnNothingWhereThereIsNothing() {
        let answers = ask(opened(), [
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/hover",
            "params": [
                "textDocument": ["uri": uri],
                "position": ["line": 0, "character": 0]
            ]
        ])

        #expect(result(answers) is NSNull || (result(answers) as? [String: Any]) != nil)
    }

    // MARK: go to definition

    @Test func goesToTheComponentAFlowNames() throws {
        func definition(atCharacter character: Int) throws -> Int {
            let answers = ask(opened(), [
                "jsonrpc": "2.0",
                "id": 4,
                "method": "textDocument/definition",
                "params": [
                    "textDocument": ["uri": uri],
                    "position": ["line": 11, "character": character]
                ]
            ])
            let location = try #require(result(answers) as? [String: Any])
            #expect(location["uri"] as? String == uri)
            return try #require(
                ((location["range"] as? [String: Any])?["start"] as? [String: Any])?["line"] as? Int
            )
        }

        // `  flow api -> db`: the first name is the component on line 1, and
        // the second is the one on line 6.
        #expect(try definition(atCharacter: 8) == 1)
        #expect(try definition(atCharacter: 15) == 6)
    }

    @Test func goesToATechnologyALibraryDeclares() throws {
        project.put("""
        library "acme" {
          name = "Acme"

          technology "cribl-stream" {
            name     = "Cribl Stream"
            category = "monitoring"
          }
        }

        """, at: "/work/threatmodel/library/acme.lib")
        project.put(payments, at: "/work/threatmodel/payments.arch")

        let text = payments.replacingOccurrences(
            of: "technology = \"aws-ec2\"",
            with: "technology = \"acme-cribl-stream\""
        )
        let answers = ask(opened(text), [
            "jsonrpc": "2.0",
            "id": 4,
            "method": "textDocument/definition",
            "params": [
                "textDocument": ["uri": uri],
                "position": ["line": 2, "character": 20]
            ]
        ])
        let location = try #require(result(answers) as? [String: Any])

        #expect(location["uri"] as? String == "file:///work/threatmodel/library/acme.lib")
        let line = ((location["range"] as? [String: Any])?["start"] as? [String: Any])?["line"]
        #expect(line as? Int == 3)
    }

    // MARK: formatting

    @Test func formatsTheDocumentTheWayFormatDoes() throws {
        let untidy = """
        system "Payments" {
        component "api" {
        technology = "aws-ec2"
        }
        }
        """
        let answers = ask(opened(untidy), [
            "jsonrpc": "2.0",
            "id": 5,
            "method": "textDocument/formatting",
            "params": ["textDocument": ["uri": uri], "options": [:]]
        ])
        let edits = try #require(result(answers) as? [[String: Any]])
        let written = try #require(edits.first?["newText"] as? String)

        #expect(written.contains("  component \"api\" {"))
        #expect(written.contains("    technology = \"aws-ec2\""))
    }

    @Test func formatsNothingWhenTheDocumentIsAlreadyCanonical() throws {
        let answers = ask(opened(), [
            "jsonrpc": "2.0",
            "id": 5,
            "method": "textDocument/formatting",
            "params": ["textDocument": ["uri": uri], "options": [:]]
        ])

        #expect((result(answers) as? [[String: Any]])?.isEmpty == true)
    }

    // MARK: the frame

    @Test func readsTheContentLengthHeader() {
        #expect(CommandLineApplication.contentLength(of: "Content-Length: 42\r\n") == 42)
        #expect(CommandLineApplication.contentLength(of: "content-length:7") == 7)
        #expect(CommandLineApplication.contentLength(of: "Content-Type: x") == nil)
    }
}
