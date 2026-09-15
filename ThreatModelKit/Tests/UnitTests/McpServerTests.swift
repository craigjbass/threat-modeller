import CommandLineApplication
import Foundation
import Testing
import ArchitectureDSL
import ThreatModelKit
import TestSupport

@Suite("Offering the model to a Model Context Protocol client")
struct McpServerTests {
    private let project = InMemoryProject(root: "/work")

    private let payments = """
    system "Payments" {
      owner = "Payments team"

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    /// A fake client: it writes one request and reads one answer, the way a
    /// real client does over a pipe.
    private func client(allowsWrites: Bool = false) -> (String) -> [String: Any] {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        let server = McpServer(
            application: CommandLineApplication(
                projects: project,
                catalogue: { CatalogueFixture.catalogue() }
            ),
            projects: project,
            root: "/work",
            allowsWrites: allowsWrites
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

    private func call(
        _ name: String,
        _ arguments: [String: Any] = [:],
        allowsWrites: Bool = false,
        with ask: ((String) -> [String: Any])? = nil
    ) -> String {
        let ask = ask ?? client(allowsWrites: allowsWrites)
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

    // MARK: the protocol

    @Test func answersInitializeWithItsOwnName() {
        let answer = client()(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}"
        )
        let result = answer["result"] as? [String: Any]

        #expect((result?["protocolVersion"] as? String) == McpServer.protocolVersion)
        #expect(((result?["serverInfo"] as? [String: Any])?["name"] as? String) == "threatmodeller")
        #expect((result?["capabilities"] as? [String: Any])?["tools"] != nil)
    }

    @Test func answersNothingToANotification() {
        let server = McpServer(
            application: CommandLineApplication(projects: project),
            projects: project,
            root: "/work",
            allowsWrites: false
        )

        #expect(server.answer(to: "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}") == nil)
    }

    @Test func refusesAMethodItDoesNotHold() {
        let answer = client()("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"dance\"}")

        #expect(((answer["error"] as? [String: Any])?["code"] as? Int) == -32601)
    }

    @Test func refusesTextThatIsNotJson() {
        let answer = client()("not json")

        #expect(((answer["error"] as? [String: Any])?["code"] as? Int) == -32700)
    }

    // MARK: the tools

    @Test func listsItsToolsWithoutTheWritingOnes() throws {
        let answer = client()("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}")
        let tools = try #require(
            (answer["result"] as? [String: Any])?["tools"] as? [[String: Any]]
        )
        let names = tools.compactMap { $0["name"] as? String }

        #expect(names.contains("list_systems"))
        #expect(names.contains("read_system"))
        #expect(names.contains("check"))
        #expect(names.contains("compile"))
        #expect(names.contains("describe_threat"))
        #expect(names.contains("describe_technology"))
        #expect(names.contains("describe_control"))
        #expect(names.contains("open_threats_above"))
        #expect(names.contains("answer_control") == false)
        #expect(names.contains("set_likelihood") == false)
    }

    @Test func listsTheWritingToolsWhenWritesAreAllowed() throws {
        let ask = client(allowsWrites: true)
        let answer = ask("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}")
        let tools = try #require(
            (answer["result"] as? [String: Any])?["tools"] as? [[String: Any]]
        )
        let names = tools.compactMap { $0["name"] as? String }

        #expect(names.contains("answer_control"))
        #expect(names.contains("set_likelihood"))
    }

    @Test func listsTheSystems() throws {
        let text = call("list_systems")
        let rows = try #require(
            try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [[String: Any]]
        )

        #expect(rows.first?["name"] as? String == "payments")
        #expect(rows.first?["owner"] as? String == "Payments team")
    }

    @Test func readsOneSystemsWholeAssessment() throws {
        let text = call("read_system", ["system": "payments"])
        let json = try #require(
            try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any]
        )

        #expect(json["schemaVersion"] != nil)
        #expect((json["system"] as? [String: Any])?["name"] as? String == "Payments")
        #expect((json["threats"] as? [[String: Any]])?.isEmpty == false)
    }

    @Test func runsCheck() {
        let text = call("check")

        #expect(text.contains("unanswered") || text.contains("\"systems\""))
    }

    /// A read-only server writes nothing, and says so.
    @Test func compileWritesNothingWhileTheServerIsReadOnly() {
        let text = call("compile")

        #expect(text.contains("read only"))
        #expect(project.text(at: "/work/threatmodel/payments.controls") == nil)
    }

    @Test func compileWritesTheFileWhenWritesAreAllowed() {
        _ = call("compile", allowsWrites: true)

        #expect(project.text(at: "/work/threatmodel/payments.controls") != nil)
    }

    @Test func describesAThreat() {
        let text = call("describe_threat", ["id": "credential-theft"])

        #expect(text.contains("credential-theft"))
        #expect(text.contains("severity: "))
        #expect(text.contains("harms: "))
    }

    @Test func describesATechnology() {
        let text = call("describe_technology", ["id": "aws-ec2"])

        #expect(text.contains("aws-ec2"))
        #expect(text.contains("raises "))
    }

    @Test func describesAControl() {
        let text = call("describe_control", ["words": "iam"])

        #expect(text.isEmpty == false)
        #expect(text.lowercased().contains("iam"))
    }

    @Test func listsTheOpenThreatsAboveALevel() {
        let text = call("open_threats_above", ["level": "high", "system": "payments"])

        #expect(text.isEmpty == false)
        #expect(text.contains("low") == false || text.contains("critical") || text.contains("high"))
    }

    @Test func refusesALevelItDoesNotHold() {
        #expect(call("open_threats_above", ["level": "urgent"]).contains("there is no level"))
    }

    @Test func refusesATooItDoesNotHold() {
        #expect(call("dance").contains("there is no tool \"dance\""))
    }

    // MARK: the files

    @Test func listsEverySourceFileAsAResource() throws {
        let answer = client()("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/list\"}")
        let resources = try #require(
            (answer["result"] as? [String: Any])?["resources"] as? [[String: Any]]
        )

        #expect(resources.contains { ($0["uri"] as? String) == "file:///work/threatmodel/payments.arch" })
        #expect(resources.allSatisfy { ($0["mimeType"] as? String) == "text/plain" })
    }

    @Test func readsOneFile() throws {
        let ask = client()
        let answer = ask("""
        {"jsonrpc":"2.0","id":1,"method":"resources/read",
         "params":{"uri":"file:///work/threatmodel/payments.arch"}}
        """)
        let contents = try #require(
            (answer["result"] as? [String: Any])?["contents"] as? [[String: Any]]
        )

        #expect((contents.first?["text"] as? String)?.contains("system \"Payments\"") == true)
    }

    @Test func refusesAFileTheProjectDoesNotHold() {
        let answer = client()("""
        {"jsonrpc":"2.0","id":1,"method":"resources/read",
         "params":{"uri":"file:///etc/passwd"}}
        """)

        #expect(answer["error"] != nil)
    }

    // MARK: writing

    @Test func refusesToWriteWhileTheServerIsReadOnly() {
        #expect(
            call("answer_control", ["threat": "credential-theft", "element": "component:api"])
                .contains("read only")
        )
    }

    @Test func answersAControlAndWritesTheFile() throws {
        let ask = client(allowsWrites: true)
        _ = call("compile", with: ask)
        let compiled = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        let source = try #require(HclControlsSource().read(compiled).source)
        let answer = try #require(source.answers.first)
        let control = try #require(answer.controls.first)

        let said = call(
            "answer_control",
            [
                "threat": answer.threatId,
                "element": answer.sourceId,
                "control": control.description,
                "status": "implemented",
                "note": "Okta"
            ],
            with: ask
        )

        #expect(said.hasPrefix("wrote "))
        let written = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("status = \"implemented\""))
        #expect(written.contains("Okta"))
    }

    @Test func setsALikelihoodFindingAndWritesTheFile() throws {
        let ask = client(allowsWrites: true)
        _ = call("compile", with: ask)
        let compiled = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        let source = try #require(HclControlsSource().read(compiled).source)
        let answer = try #require(source.answers.first)

        let said = call(
            "set_likelihood",
            [
                "threat": answer.threatId,
                "element": answer.sourceId,
                "label": "Seen in the wild",
                "tier": "commodity",
                "rationale": "A public exploit exists."
            ],
            with: ask
        )

        #expect(said.hasPrefix("wrote "))
        let written = try #require(project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("likelihood \"Seen in the wild\" {"))
        #expect(written.contains("tier      = \"commodity\"") || written.contains("tier = \"commodity\""))
    }

    @Test func refusesToAnswerAThreatTheSystemDoesNotRaise() {
        let ask = client(allowsWrites: true)
        _ = call("compile", with: ask)

        #expect(
            call(
                "answer_control",
                ["threat": "nothing", "element": "component:api", "control": "x", "status": "implemented"],
                with: ask
            ).contains("raises no")
        )
    }
}
