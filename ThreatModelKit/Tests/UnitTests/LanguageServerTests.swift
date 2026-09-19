import ArchitectureDSL
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

    // MARK: semantic tokens

    /// The tokens one document answers, as the protocol's flat array.
    private func semanticTokens(_ text: String, at uri: String) -> [Int] {
        let answers = ask(opened(text, at: uri), [
            "jsonrpc": "2.0",
            "id": 2,
            "method": "textDocument/semanticTokens/full",
            "params": ["textDocument": ["uri": uri]]
        ])
        return (result(answers) as? [String: Any])?["data"] as? [Int] ?? []
    }

    @Test func statesTheSemanticTokensLegend() throws {
        let answers = ask(server(), ["jsonrpc": "2.0", "id": 1, "method": "initialize", "params": [:]])
        let capabilities = try #require(
            (result(answers) as? [String: Any])?["capabilities"] as? [String: Any]
        )
        let provider = try #require(capabilities["semanticTokensProvider"] as? [String: Any])
        let legend = try #require(provider["legend"] as? [String: Any])

        #expect(
            legend["tokenTypes"] as? [String]
                == ["keyword", "string", "number", "comment", "operator", "variable"]
        )
        #expect(legend["tokenModifiers"] as? [String] == [])
        #expect(provider["full"] as? Bool == true)
    }

    @Test func encodesTheTokensOfAnArchitectureFile() {
        let data = semanticTokens("""
        # a note
        system "Payments" {
          flow api -> db
        }
        """, at: "file:///work/threatmodel/small.arch")

        #expect(data == [
            0, 0, 8, 3, 0,
            1, 0, 6, 0, 0,
            0, 7, 10, 5, 0,
            1, 2, 4, 0, 0,
            0, 5, 3, 5, 0,
            0, 4, 2, 4, 0,
            0, 3, 2, 5, 0
        ])
    }

    @Test func encodesTheTokensOfAControlsFile() {
        let data = semanticTokens("""
        controls for "Payments" {
          score = 40
        }
        """, at: "file:///work/threatmodel/small.controls")

        #expect(data == [
            0, 0, 8, 0, 0,
            0, 9, 3, 0, 0,
            0, 4, 10, 5, 0,
            1, 2, 5, 0, 0,
            0, 8, 2, 2, 0
        ])
    }

    @Test func encodesTheTokensOfALibraryFile() {
        let data = semanticTokens("""
        library "endpoint" {
          encrypts = true
        }
        """, at: "file:///work/libraries/small.lib")

        #expect(data == [
            0, 0, 7, 0, 0,
            0, 8, 10, 5, 0,
            1, 2, 8, 0, 0,
            0, 11, 4, 0, 0
        ])
    }

    @Test func encodesTheTokensOfAnAttackTreeFile() {
        let data = semanticTokens("""
        attack_trees for "Payments" {
          raises_risk_by = 40
        }
        """, at: "file:///work/threatmodel/small.attacktree")

        #expect(data == [
            0, 0, 12, 0, 0,
            0, 13, 3, 0, 0,
            0, 4, 10, 5, 0,
            1, 2, 14, 0, 0,
            0, 17, 2, 2, 0
        ])
    }

    @Test func coloursThenAsAKeywordInAnAttackTreeFile() {
        let data = semanticTokens("""
        attack_trees for "Payments" {
          then {
          }
        }
        """, at: "file:///work/threatmodel/small.attacktree")

        #expect(data == [
            0, 0, 12, 0, 0,
            0, 13, 3, 0, 0,
            0, 4, 10, 5, 0,
            1, 2, 4, 0, 0
        ])
    }

    @Test func encodesTheTokensOfAGovernanceFile() {
        let data = semanticTokens("""
        governance for "Payments" {
          owner = "team"
        }
        """, at: "file:///work/threatmodel/small.governance")

        #expect(data == [
            0, 0, 10, 0, 0,
            0, 11, 3, 0, 0,
            0, 4, 10, 5, 0,
            1, 2, 5, 0, 0,
            0, 8, 6, 1, 0
        ])
    }

    @Test func encodesTheTokensOfAPolicyFile() {
        let data = semanticTokens("""
        policy {
          # a note
          accepted_requires_owner = true
        }
        """, at: "file:///work/threatmodel/policy.hcl")

        #expect(data == [
            0, 0, 6, 0, 0,
            1, 2, 8, 3, 0,
            1, 2, 23, 0, 0,
            0, 26, 4, 0, 0
        ])
    }

    @Test func encodesTheTokensOfAFileThatDoesNotParse() {
        let data = semanticTokens("""
        system "Payments" {
          component
        """, at: "file:///work/threatmodel/broken.arch")

        #expect(data == [
            0, 0, 6, 0, 0,
            0, 7, 10, 5, 0,
            1, 2, 9, 0, 0
        ])
    }

    @Test func answersAnEmptyArrayForAnEmptyDocument() {
        #expect(semanticTokens("", at: "file:///work/threatmodel/empty.arch") == [])
    }

    /// One token of the wire format, decoded from the five-number deltas back
    /// to an absolute line and column.
    private struct DecodedToken: Equatable {
        let line: Int
        let column: Int
        let length: Int
        let type: Int
    }

    private func decoded(_ data: [Int]) -> [DecodedToken] {
        var line = 0
        var column = 0
        var tokens: [DecodedToken] = []
        var index = 0
        while index + 4 < data.count {
            line += data[index]
            column = data[index] == 0 ? column + data[index + 1] : data[index + 1]
            tokens.append(DecodedToken(line: line, column: column, length: data[index + 2], type: data[index + 3]))
            index += 5
        }
        return tokens
    }

    @Test func sendsNoTokenPastTheEndOfTheLineAHeredocOpensOn() {
        let data = semanticTokens("""
        <<EOT
        one
        two
        EOT
        """, at: "file:///work/threatmodel/small.arch")

        #expect(decoded(data) == [DecodedToken(line: 0, column: 0, length: 5, type: 1)])
    }

    @Test func sendsTheLexersLineOneColumnOneAsLineZeroColumnZero() {
        let data = semanticTokens("true", at: "file:///work/threatmodel/tiny.arch")

        #expect(data == [0, 0, 4, 0, 0])
    }

    @Test func leavesOutEveryTokenForALineAHeredocSwallows() {
        let data = semanticTokens("""
        x = <<EOT
        one
        two
        EOT
        y = 2
        """, at: "file:///work/threatmodel/small.arch")

        let heldLines = decoded(data).map(\.line)
        #expect(Set(heldLines).isDisjoint(with: [1, 2, 3]))
        #expect(heldLines.contains(4))
    }

    @Test func coloursTheIdentifierAMitigatesBlockNamesAsAVariable() {
        let data = semanticTokens("""
        system "Payments" {
          mitigates api {
          }
        }
        """, at: "file:///work/threatmodel/small.arch")

        #expect(decoded(data).contains(DecodedToken(line: 1, column: 12, length: 3, type: 5)))
    }

    @Test func readsTheExtensionsSamplePolicyWithNoDiagnostic() throws {
        let text = try Self.fixtureText("vscode/test-fixtures/project/policy.hcl")
        let uri = "file:///work/threatmodel/policy.hcl"
        let answers = ask(server(), [
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": ["textDocument": ["uri": uri, "text": text]]
        ])
        let diagnostics = try #require(
            (answers.first?["params"] as? [String: Any])?["diagnostics"] as? [[String: Any]]
        )

        #expect(diagnostics.isEmpty)
    }

    private static func fixtureText(_ path: String) throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try String(contentsOf: root.appendingPathComponent(path), encoding: .utf8)
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

    private let people = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
      }

      user "alice" {
        r
      }

      flow a
    }

    """

    @Test func completesTheAttributesOfAUserBlock() {
        let labels = completions(opened(people), line: 6, character: 5)

        #expect(labels.contains("role"))
        #expect(labels.contains("access"))
        #expect(labels.contains("uses"))
        #expect(labels.contains("reaches"))
        #expect(labels.contains("threat_actor"))
    }

    @Test func completesAUserIdInAFlow() {
        let labels = completions(opened(people), line: 9, character: 8)

        #expect(labels.contains("alice"))
        #expect(labels.contains("api"))
    }

    @Test func completesTheAttributesOfTheBlockTheCursorSitsIn() {
        let labels = completions(opened(), line: 3, character: 4)

        #expect(labels.contains("technology"))
        #expect(labels.contains("runs_as"))
        #expect(labels.contains("holds"))
        #expect(labels.contains("zone"))
        #expect(labels.contains("version"))
        #expect(labels.contains("cves"))
    }

    // MARK: completion lists come from LanguageVocabulary

    /// `LanguageServer.attributes` reads `LanguageVocabulary`, so a
    /// completion list this test did not name still tracks the parser.
    @Test func offersReferenceAndVerifiedOnOnAControlAndNeverSays() {
        let attributes = LanguageServer.attributes(of: "control", language: .controls)

        #expect(attributes.contains("reference"))
        #expect(attributes.contains("verified_on"))
        #expect(attributes.contains("says") == false)
    }

    @Test func offersTheArchTechnologyAttributesTheParserReads() {
        let attributes = LanguageServer.attributes(of: "technology", language: .architecture)

        #expect(attributes == LanguageBlockId.archTechnology.block.attributes)
    }

    @Test func offersControlOnALibraryTechnology() {
        let attributes = LanguageServer.attributes(of: "technology", language: .library)

        #expect(attributes.contains("control"))
    }

    @Test func completesTheWordsOfATreeBlock() {
        let trees = """
        attack_trees for "Payments" {
          tree "t" {
            t
          }
        }

        """
        let server = opened(trees, at: "file:///work/threatmodel/payments.attacktree")
        let labels = completions(
            server,
            line: 2,
            character: 5,
            at: "file:///work/threatmodel/payments.attacktree"
        )

        #expect(labels.contains("then"))
        #expect(labels.contains("all_of"))
        #expect(labels.contains("step"))
        #expect(labels.contains("raises_risk_by"))
    }

    @Test func completesTheWordsOfAJunction() {
        let trees = """
        attack_trees for "Payments" {
          tree "t" {
            then {
              s
            }
          }
        }

        """
        let server = opened(trees, at: "file:///work/threatmodel/payments.attacktree")
        let labels = completions(
            server,
            line: 3,
            character: 7,
            at: "file:///work/threatmodel/payments.attacktree"
        )

        #expect(labels.contains("step"))
        #expect(labels.contains("then"))
        #expect(labels.contains("any_of"))
        #expect(labels.contains("raises_risk_by") == false)
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


    // MARK: every block of every language

    /// One document that nests a block where its language nests it, and the
    /// place a person's cursor sits inside it.
    private struct Sample {
        let text: String
        let uri: String
        let line: Int
        let character: Int
    }

    private static func fileName(of language: String) -> String {
        language == "policy" ? "policy.hcl" : "walk.\(language)"
    }

    /// The line one block opens on, as its language writes it.
    private static func header(of id: LanguageBlockId) -> String {
        let keyword = id.block.keywords[0]
        switch keyword {
        case "controls", "attack_trees", "governance":
            return "\(keyword) for \"Payments\" {"
        case "policy":
            return "policy {"
        case "flow", "mitigates":
            return "\(keyword) api -> db {"
        case "all_of", "any_of", "then":
            return "\(keyword) {"
        case "threat" where id.block.language != "lib":
            return "threat \"credential-theft\" on component \"api\" {"
        case "step" where id.block.language == "attacktree":
            return "step \"read the store\" on component \"api\" {"
        default:
            return "\(keyword) \"one\" {"
        }
    }

    private static func sample(of id: LanguageBlockId) -> Sample {
        var chain: [LanguageBlockId] = [id]
        while let parent = chain[0].block.within.first {
            chain.insert(parent, at: 0)
        }

        var lines = chain.enumerated().map { depth, each in
            String(repeating: "  ", count: depth) + header(of: each)
        }
        let indent = String(repeating: "  ", count: chain.count)
        lines.append(indent)
        for depth in stride(from: chain.count - 1, through: 0, by: -1) {
            lines.append(String(repeating: "  ", count: depth) + "}")
        }

        return Sample(
            text: lines.joined(separator: "\n") + "\n",
            uri: "file:///work/threatmodel/" + fileName(of: id.block.language),
            line: chain.count,
            character: indent.count
        )
    }

    @Test func completesTheAttributesOfEveryBlockTheVocabularyDeclares() {
        for id in LanguageBlockId.allCases {
            let sample = Self.sample(of: id)
            let labels = completions(
                opened(sample.text, at: sample.uri),
                line: sample.line,
                character: sample.character,
                at: sample.uri
            )
            let missing = id.block.attributes.filter { labels.contains($0) == false }

            #expect(
                missing.isEmpty,
                """
                Inside \(id.rawValue) the server offers no \
                \(missing.joined(separator: ", ")). The block opens with \
                \(id.block.keywords.joined(separator: " or ")).
                """
            )
        }
    }

    @Test func completesTheAttributesOfAUseBlock() {
        let text = """
        system "Payments" {
          user "alice" {
            uses "browser" {
              r
            }
          }
        }

        """
        let labels = completions(opened(text), line: 3, character: 7)

        #expect(labels.contains("reaches"))
    }

    @Test func completesTheAttributesOfACompensatingControl() {
        let controls = """
        controls for "Payments" {
          threat "credential-theft" on component "api" {
            compensating "Break glass" {
              r
            }
          }
        }

        """
        let uri = "file:///work/threatmodel/payments.controls"
        let labels = completions(opened(controls, at: uri), line: 3, character: 7, at: uri)

        #expect(labels.contains("reduces_risk_by"))
        #expect(labels.contains("rationale"))
        #expect(labels.contains("verified_on"))
    }

    @Test func completesTheAttributesOfALikelihoodFinding() {
        let controls = """
        controls for "Payments" {
          threat "credential-theft" on component "api" {
            likelihood "no campaign names this" {
              t
            }
          }
        }

        """
        let uri = "file:///work/threatmodel/payments.controls"
        let labels = completions(opened(controls, at: uri), line: 3, character: 7, at: uri)

        #expect(labels.contains("tier"))
        #expect(labels.contains("prior"))
        #expect(labels.contains("rationale"))
    }

    @Test func completesTheAttributesOfAControlsTree() {
        let controls = """
        controls for "Payments" {
          tree "t" {
            g
          }
        }

        """
        let uri = "file:///work/threatmodel/payments.controls"
        let labels = completions(opened(controls, at: uri), line: 2, character: 5, at: uri)

        #expect(labels.contains("goal"))
        #expect(labels.contains("chain"))
        #expect(labels.contains("score_before"))
        #expect(labels.contains("sufficient"))
    }

    @Test func completesTheAttributesOfALibraryMitigation() {
        let library = """
        library "acme" {
          mitigation "m" {
            m
          }
        }

        """
        let uri = "file:///work/libraries/acme.lib"
        let labels = completions(opened(library, at: uri), line: 2, character: 5, at: uri)

        #expect(labels.contains("mitigates"))
        #expect(labels.contains("provided_by"))
        #expect(labels.contains("reduces_risk_by"))
        #expect(labels.contains("mode"))
    }

    @Test func completesTheAttributesOfAGovernanceFile() {
        let governance = """
        governance for "Payments" {
          t
        }

        """
        let uri = "file:///work/threatmodel/payments.governance"
        let labels = completions(opened(governance, at: uri), line: 1, character: 3, at: uri)

        #expect(labels.contains("threat"))
        #expect(labels.contains("action"))
        #expect(labels.contains("stale threat"))
    }

    // MARK: hover

    private func hovered(
        _ server: LanguageServer,
        line: Int,
        character: Int,
        at uri: String? = nil
    ) -> String {
        let answers = ask(server, [
            "jsonrpc": "2.0",
            "id": 3,
            "method": "textDocument/hover",
            "params": [
                "textDocument": ["uri": uri ?? self.uri],
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


    @Test func hoversOnACapabilityTierWithItsFactor() {
        let text = """
        system "Payments" {
          threat_actor "spy" {
            capability = "insider"
          }
        }

        """
        let said = hovered(opened(text), line: 2, character: 19)

        #expect(said.contains("Insider"))
        #expect(said.contains("0.6"))
    }

    @Test func hoversOnAClearanceWithItsReductionAndItsRationale() {
        let text = """
        system "Payments" {
          clearance "sc" {
            name                    = "Security Check"
            reduces_insider_risk_by = 60
            rationale               = "The vetting reads the whole employment record."
          }

          user "alice" {
            clearance = "sc"
          }
        }

        """
        let said = hovered(opened(text), line: 8, character: 18)

        #expect(said.contains("60"))
        #expect(said.contains("The vetting reads the whole employment record."))
    }

    @Test func hoversOnACompensatingControlWithItsReductionAndItsRationale() {
        let controls = """
        controls for "Payments" {
          threat "credential-theft" on component "api" {
            compensating "Break-glass account watched by the SIEM" {
              reduces_risk_by = 40
              rationale       = "The one account left alerts on use."
            }
          }
        }

        """
        let uri = "file:///work/threatmodel/payments.controls"
        let said = hovered(opened(controls, at: uri), line: 2, character: 20, at: uri)

        #expect(said.contains("40"))
        #expect(said.contains("The one account left alerts on use."))
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
