import ArchitectureDSL
import CommandLineApplication
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// Every place that refuses an unknown likelihood word names the tiers from
/// `Likelihood.allTiers`.
///
/// `allTiers` is a `static let` with no seam to add a tier in a test, so
/// each check states the property the other way: the message holds every
/// word `allTiers` holds today, so a tier this application adds later needs
/// no change at the site the check drives.
@Suite("Every place that refuses an unknown tier names it from Likelihood.allTiers")
struct LikelihoodTierParityTests {
    private let words = Likelihood.allTiers.map(\.id)

    private func holdsEveryWord(_ message: String) -> Bool {
        words.allSatisfy(message.contains)
    }

    private let architecture = HclArchitectureSource()
    private let libraries = HclLibrarySource()

    private func architectureErrors(_ text: String) -> [String] {
        architecture.read(text).diagnostics.filter { $0.severity == .error }.map(\.message)
    }

    private func libraryErrors(_ text: String) -> [String] {
        libraries.read(text).diagnostics.filter { $0.severity == .error }.map(\.message)
    }

    // MARK: parsers

    @Test func architectureParserNamesEveryTierForAnUnknownCapability() {
        let messages = architectureErrors("""
        system "Payments" {
          threat_actor "insider" {
            name       = "Someone"
            capability = "folklore"
          }
        }
        """)

        #expect(messages.contains { holdsEveryWord($0) })
    }

    @Test func architectureParserNamesEveryTierForAnUnknownCatalogueTier() {
        let messages = architectureErrors("""
        system "Payments" {
          threat_actor "insider" {
            name                    = "Someone"
            performs_catalogue_tier = "folklore"
          }
        }
        """)

        #expect(messages.contains { holdsEveryWord($0) })
    }

    @Test func libraryParserNamesEveryTierForAnUnknownCapability() {
        let messages = libraryErrors("""
        library "acme" {
          threat_actor "insider" {
            name       = "Someone"
            capability = "folklore"
          }
        }
        """)

        #expect(messages.contains { holdsEveryWord($0) })
    }

    @Test func libraryParserNamesEveryTierForAnUnknownCatalogueTier() {
        let messages = libraryErrors("""
        library "acme" {
          threat_actor "insider" {
            name                    = "Someone"
            performs_catalogue_tier = "folklore"
          }
        }
        """)

        #expect(messages.contains { holdsEveryWord($0) })
    }

    @Test func libraryParserNamesEveryTierForAnUnknownOverrideLikelihood() {
        let messages = libraryErrors("""
        library "acme" {
          override "credential-theft" {
            likelihood = "folklore"
          }
        }
        """)

        #expect(messages.contains { holdsEveryWord($0) })
    }

    // MARK: use cases

    @Test func setLikelihoodFindingNamesEveryTierForAnUnknownTier() {
        var message: String?
        SetLikelihoodFindingResponse.unknownTier.describe(into: &message)

        #expect(message.map(holdsEveryWord) == true)
    }

    @Test func writeLikelihoodFindingNamesEveryTierForAnUnknownTier() {
        let app = TestDependencies()
        app.project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )

        let response = app.writeLikelihoodFinding().execute(
            WriteLikelihoodFindingRequest(
                root: "/work",
                systemName: "payments",
                systemDisplayName: "Payments",
                threatId: "credential-theft",
                sourceKind: "component",
                sourceId: "api",
                label: "no campaign has used this against our stack",
                tier: "folklore",
                prior: nil,
                rationale: "No public reporting names this technique against this platform.",
                sources: []
            )
        )

        guard case .refused(let reason) = response else {
            Issue.record("expected a refusal, got \(response)")
            return
        }
        #expect(holdsEveryWord(reason))
    }

    // MARK: the MCP tool

    private let payments = """
    system "Payments" {
      owner = "Payments team"

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func mcpClient(project: InMemoryProject) -> (String) -> [String: Any] {
        let server = McpServer(
            application: CommandLineApplication(
                projects: project,
                catalogue: { CatalogueFixture.catalogue() }
            ),
            projects: project,
            root: "/work",
            allowsWrites: true
        )
        return { request in
            guard let text = server.answer(to: request),
                  let data = text.data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                Issue.record("the server did not answer \(request)")
                return [:]
            }
            return json
        }
    }

    private func mcpCall(
        _ name: String,
        _ arguments: [String: Any],
        with ask: (String) -> [String: Any]
    ) -> String {
        let request: [String: Any] = [
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": ["name": name, "arguments": arguments]
        ]
        let data = try? JSONSerialization.data(withJSONObject: request)
        let answer = ask(String(decoding: data ?? Data(), as: UTF8.self))
        guard let result = answer["result"] as? [String: Any],
              let content = result["content"] as? [[String: Any]],
              let text = content.first?["text"] as? String else {
            return (answer["error"] as? [String: Any])?["message"] as? String ?? ""
        }
        return text
    }

    @Test func mcpServerNamesEveryTierInTheSetLikelihoodToolDescription() {
        let project = InMemoryProject(root: "/work")
        project.put(payments, at: "/work/threatmodel/payments.arch")
        let ask = mcpClient(project: project)

        let answer = ask(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"
        )
        let tools = (answer["result"] as? [String: Any])?["tools"] as? [[String: Any]] ?? []
        let setLikelihood = tools.first { $0["name"] as? String == "set_likelihood" }
        let properties = (setLikelihood?["inputSchema"] as? [String: Any])?["properties"]
            as? [String: Any]
        let tierDescription = (properties?["tier"] as? [String: Any])?["description"] as? String

        #expect(tierDescription.map(holdsEveryWord) == true)
    }

    @Test func mcpServerNamesEveryTierWhenSetLikelihoodRefusesAnUnknownTier() throws {
        let project = InMemoryProject(root: "/work")
        project.put(payments, at: "/work/threatmodel/payments.arch")
        let ask = mcpClient(project: project)
        _ = mcpCall("compile", [:], with: ask)
        let compiled = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        let source = try #require(HclControlsSource().read(compiled).source)
        let answer = try #require(source.answers.first)

        let said = mcpCall(
            "set_likelihood",
            [
                "threat": answer.threatId,
                "element": answer.sourceId,
                "label": "Seen in the wild",
                "tier": "folklore",
                "rationale": "A public exploit exists."
            ],
            with: ask
        )

        #expect(holdsEveryWord(said))
    }
}
