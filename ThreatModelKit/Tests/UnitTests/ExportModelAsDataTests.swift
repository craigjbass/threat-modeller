import Foundation
import CommandLineApplication
import Testing
import ThreatModelKit
import TestSupport

@Suite("Writing the assessed model as data")
struct ExportModelAsDataTests {
    private let project = InMemoryProject(root: "/work")

    /// One sample system, held here so the golden files below state what the
    /// export writes for a model a reader can see.
    private let payments = """
    system "Payments" {
      owner = "Payments team"

      asset "card-numbers" {
        name           = "Card numbers"
        classification = "restricted"
        owner          = "Payments team"
      }

      third_party "stripe" {
        name   = "Stripe"
        uptime = "degraded"
      }

      assumption "network-segmented" {
        text = "The VPC has no route to the internet."
      }

      use_case "take-a-payment" {
        text = "A customer pays for a basket."
      }

      exclusion "the card network" {
        text      = "This model does not cover the card network."
        rationale = "Another team owns it."
      }

      zone "app" {
        kind = "private"

        component "api" {
          technology  = "aws-ec2"
          holds       = ["card-numbers"]
          provided_by = "stripe"
        }
      }
    }

    """

    private func run(_ words: String...) -> (code: Int32, lines: [String]) {
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller"] + words, output: { lines.append($0) })
        return (code, lines)
    }

    private func aProject() {
        project.put(payments, at: "/work/threatmodel/payments.arch")
    }

    private func written(_ path: String) throws -> [String: Any] {
        let text = try #require(project.text(at: path))
        let data = Data(text.utf8)
        return try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    // MARK: the JSON shape

    @Test func writesOneJsonFilePerSystem() throws {
        aProject()

        let run = self.run("export", "/work", "--format", "json")

        #expect(run.code == 0)
        let json = try written("/work/threatmodel/payments.json")
        #expect(json["schemaVersion"] as? String == ExportModelAsJson.schemaVersion)
        let system = try #require(json["system"] as? [String: Any])
        #expect(system["name"] as? String == "Payments")
        #expect(system["owner"] as? String == "Payments team")
    }

    @Test func theFileHoldsEveryPartOfTheModel() throws {
        aProject()
        _ = run("export", "/work", "--format", "json")

        let json = try written("/work/threatmodel/payments.json")
        for key in [
            "assets", "assumptions", "components", "exclusions", "flows", "leverage",
            "recommendations", "summary", "system", "threats", "thirdParties", "useCases",
            "zones", "acceptedRisks"
        ] {
            #expect(json[key] != nil, "the export writes no \(key)")
        }

        let components = try #require(json["components"] as? [[String: Any]])
        #expect(components.first?["id"] as? String == "api")
        #expect(components.first?["zoneName"] as? String == "Private Zone")

        let assets = try #require(json["assets"] as? [[String: Any]])
        #expect(assets.first?["name"] as? String == "Card numbers")

        let threats = try #require(json["threats"] as? [[String: Any]])
        #expect(threats.isEmpty == false)
        let first = try #require(threats.first)
        for key in ["controls", "id", "impacts", "isOpen", "riskLevel", "riskScore", "sourceId"] {
            #expect(first[key] != nil, "a threat states no \(key)")
        }
    }

    @Test func theSummaryCountsWhatTheReportCounts() throws {
        aProject()
        _ = run("export", "/work", "--format", "json")

        let json = try written("/work/threatmodel/payments.json")
        let summary = try #require(json["summary"] as? [String: Any])
        let threats = try #require(json["threats"] as? [[String: Any]])

        #expect(summary["totalThreats"] as? Int == threats.count)
        #expect(summary["unansweredThreats"] as? Int == threats.filter { $0["isOpen"] as? Bool == true }.count)
    }

    /// Two exports of one model are the same bytes, so a file in a repository
    /// changes only when the model changes.
    @Test func twoExportsOfOneModelAreTheSameBytes() throws {
        aProject()

        _ = run("export", "/work", "--format", "json")
        let first = try #require(project.text(at: "/work/threatmodel/payments.json"))
        _ = run("export", "/work", "--format", "json")
        let second = try #require(project.text(at: "/work/threatmodel/payments.json"))

        #expect(first == second)
    }

    @Test func writesIntoTheDirectoryTheUserNames() throws {
        aProject()

        let run = self.run("export", "/work", "--format", "json", "-o", "/out")

        #expect(run.code == 0)
        #expect(project.text(at: "/out/payments.json") != nil)
    }

    /// A pipeline reads one system without a temporary directory.
    @Test func writesOneSystemToStandardOutput() throws {
        aProject()

        let run = self.run("export", "/work", "--format", "json", "--stdout")

        #expect(run.code == 0)
        #expect(project.text(at: "/work/threatmodel/payments.json") == nil)
        let text = run.lines.joined(separator: "\n")
        let json = try #require(
            try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any]
        )
        #expect((json["system"] as? [String: Any])?["name"] as? String == "Payments")
    }

    @Test func standardOutputRefusesAProjectOfManySystems() throws {
        aProject()
        project.put(payments.replacingOccurrences(of: "Payments", with: "Ledger"),
                    at: "/work/threatmodel/ledger.arch")

        let refused = self.run("export", "/work", "--format", "json", "--stdout")

        #expect(refused.code == CommandLineApplication.ExitCode.didNotParse.rawValue)
        #expect(refused.lines == [
            "threatmodeller: this project holds more than one system,"
                + " so --stdout writes none; name one root or drop the flag"
        ])

        project.put(payments, at: "/work/payments/threatmodel/payments.arch")
        let named = self.run("export", "/work/payments", "--format", "json", "--stdout")

        #expect(named.code == 0)
        let json = try #require(
            try JSONSerialization.jsonObject(
                with: Data(named.lines.joined(separator: "\n").utf8)
            ) as? [String: Any]
        )
        #expect((json["system"] as? [String: Any])?["name"] as? String == "Payments")
    }

    @Test func refusesAFormatItDoesNotWrite() {
        aProject()

        let run = self.run("export", "/work", "--format", "yaml")

        #expect(run.code != 0)
        #expect(run.lines.contains { $0.contains("there is no export format \"yaml\"") })
    }

    // MARK: the Open Threat Model shape

    @Test func writesAnOpenThreatModelFile() throws {
        aProject()

        let run = self.run("export", "/work", "--format", "otm")

        #expect(run.code == 0)
        let json = try written("/work/threatmodel/payments.otm.json")
        #expect(json["otmVersion"] as? String == ExportModelAsOtm.otmVersion)

        let project_ = try #require(json["project"] as? [String: Any])
        #expect(project_["name"] as? String == "Payments")
        #expect(project_["id"] as? String == "Payments")

        let zones = try #require(json["trustZones"] as? [[String: Any]])
        #expect(zones.first?["id"] as? String == "private-zone")

        let components = try #require(json["components"] as? [[String: Any]])
        #expect(components.first?["id"] as? String == "api")
        #expect(
            (components.first?["parent"] as? [String: Any])?["trustZone"] as? String
                == "private-zone"
        )

        let threats = try #require(json["threats"] as? [[String: Any]])
        #expect(threats.isEmpty == false)
        let risk = try #require(threats.first?["risk"] as? [String: Any])
        #expect(risk["score"] != nil)
        #expect(risk["likelihood"] != nil)
    }

    /// One threat on many elements is one OTM threat per pair, so no score is
    /// lost where OTM keys a threat once.
    @Test func eachThreatAndElementPairIsOneOpenThreatModelThreat() throws {
        aProject()
        _ = run("export", "/work", "--format", "otm")
        _ = run("export", "/work", "--format", "json")

        let otm = try written("/work/threatmodel/payments.otm.json")
        let ours = try written("/work/threatmodel/payments.json")

        let otmThreats = try #require(otm["threats"] as? [[String: Any]])
        let ourThreats = try #require(ours["threats"] as? [[String: Any]])
        #expect(otmThreats.count == ourThreats.count)
        #expect(Set(otmThreats.compactMap { $0["id"] as? String }).count == otmThreats.count)
    }

    @Test func twoOpenThreatModelExportsAreTheSameBytes() throws {
        aProject()

        _ = run("export", "/work", "--format", "otm")
        let first = try #require(project.text(at: "/work/threatmodel/payments.otm.json"))
        _ = run("export", "/work", "--format", "otm")
        let second = try #require(project.text(at: "/work/threatmodel/payments.otm.json"))

        #expect(first == second)
    }

    // MARK: the golden files

    /// The whole file, byte for byte, for one sample system. A change to the
    /// export shows here as a diff a reader can read, and the file under
    /// `Tests/Goldens` is what `docs/threatmodel-export.schema.json` states.
    @Test func theJsonExportMatchesTheGoldenFile() throws {
        aProject()
        _ = run("export", "/work", "--format", "json")

        let written = try #require(project.text(at: "/work/threatmodel/payments.json"))
        let golden = try Self.golden("payments-export.json")

        #expect(written == golden)
    }

    @Test func theOpenThreatModelExportMatchesTheGoldenFile() throws {
        aProject()
        _ = run("export", "/work", "--format", "otm")

        let written = try #require(project.text(at: "/work/threatmodel/payments.otm.json"))
        let golden = try Self.golden("payments-export.otm.json")

        #expect(written == golden)
    }

    /// Writes the golden files from the sample system. It is not a test: set
    /// `THREATMODELLER_WRITE_GOLDENS=1` and run the suite to write them again
    /// after a change to the export that a reader has agreed.
    @Test func writesTheGoldenFilesWhenAskedTo() throws {
        guard ProcessInfo.processInfo.environment["THREATMODELLER_WRITE_GOLDENS"] == "1" else {
            return
        }
        aProject()
        _ = run("export", "/work", "--format", "json")
        _ = run("export", "/work", "--format", "otm")

        let directory = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Goldens")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try #require(project.text(at: "/work/threatmodel/payments.json"))
            .write(
                to: directory.appendingPathComponent("payments-export.json"),
                atomically: true,
                encoding: .utf8
            )
        try #require(project.text(at: "/work/threatmodel/payments.otm.json"))
            .write(
                to: directory.appendingPathComponent("payments-export.otm.json"),
                atomically: true,
                encoding: .utf8
            )
    }

    /// The golden files sit beside the tests, so a reader opens one and sees
    /// what the export writes.
    private static func golden(_ name: String) throws -> String {
        let path = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Goldens")
            .appendingPathComponent(name)
        return try String(contentsOf: path, encoding: .utf8)
    }

    @Test func theDefaultFormatIsJson() throws {
        aProject()

        let run = self.run("export", "/work")

        #expect(run.code == 0)
        #expect(project.text(at: "/work/threatmodel/payments.json") != nil)
    }
}

@Suite("Drawing the diagram as text a wiki renders")
struct TextDiagramVerbTests {
    private let project = InMemoryProject(root: "/work")

    private let payments = """
    system "Payments" {
      zone "app" {
        kind = "private"

        component "api" {
          technology = "aws-ec2"
          data       = "confidential"
        }
      }

      component "attacker" {
        technology = "actor-attacker"
      }

      flow attacker -> api
    }

    """

    private func run(_ words: String...) -> (code: Int32, lines: [String]) {
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller"] + words, output: { lines.append($0) })
        return (code, lines)
    }

    private func aProject() {
        project.put(payments, at: "/work/threatmodel/payments.arch")
    }

    @Test func drawWritesMermaidBesideTheSvg() throws {
        aProject()

        #expect(run("draw", "/work", "--svg", "--mermaid").code == 0)

        #expect(project.text(at: "/work/threatmodel/payments.svg") != nil)
        let mermaid = try #require(project.text(at: "/work/threatmodel/payments.mmd"))
        #expect(mermaid.hasPrefix("flowchart LR"))
        #expect(mermaid.contains("subgraph app"))
    }

    @Test func drawWritesGraphvizAndD2() throws {
        aProject()

        #expect(run("draw", "/work", "--dot", "--d2").code == 0)

        let dot = try #require(project.text(at: "/work/threatmodel/payments.dot"))
        #expect(dot.hasPrefix("digraph {"))
        let d2 = try #require(project.text(at: "/work/threatmodel/payments.d2"))
        #expect(d2.contains("shape: rectangle"))
    }

    @Test func twoRunsWriteTheSameBytes() throws {
        aProject()

        _ = run("draw", "/work", "--mermaid")
        let first = try #require(project.text(at: "/work/threatmodel/payments.mmd"))
        _ = run("draw", "/work", "--mermaid")
        let second = try #require(project.text(at: "/work/threatmodel/payments.mmd"))

        #expect(first == second)
    }

    /// A wiki renders the report with no image file beside it.
    @Test func theReportHoldsTheDiagramItself() throws {
        aProject()

        #expect(run("report", "/work", "--diagram", "mermaid", "--commits", "0").code == 0)

        let report = try #require(project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.contains("```mermaid"))
        #expect(report.contains("flowchart LR"))
        #expect(report.contains("![") == false)
        #expect(project.text(at: "/work/threatmodel/payments-threat-1.svg") == nil)
    }

    @Test func theReportStillWritesThePicturesWhenNobodyAsksForText() throws {
        aProject()

        #expect(run("report", "/work", "--commits", "0").code == 0)

        let report = try #require(project.text(at: "/work/threatmodel/payments.md"))
        #expect(report.contains("```mermaid") == false)
        #expect(report.contains("!["))
    }

    @Test func theReportRefusesALanguageItDoesNotWrite() {
        aProject()

        let run = self.run("report", "/work", "--diagram", "plantuml")

        #expect(run.code != 0)
        #expect(run.lines.contains { $0.contains("there is no report diagram language") })
    }
}

/// The JSON export carries the people, the trees, the diagrams and the
/// decisions a threat holds, and the file it writes matches the schema the
/// repository publishes.
@Suite("The exports carry the people, the trees and the decisions")
struct ExportCarriesThePeopleTheTreesAndTheDecisionsTests {
    private let app = TestDependencies()

    private let payments = """
    system "Payments" {
      threat_actor "insider" {
        name       = "Disgruntled operator"
        capability = "targeted"
        intent     = "sabotage"
        performs   = ["credential-theft"]
      }

      clearance "sc" {
        name                    = "Security Check"
        reduces_insider_risk_by = 60
        rationale               = "The vetting reads the whole employment record."
      }

      diagram "The login sequence" {
        kind = "mermaid"
        text = <<EOT
    sequenceDiagram
      Customer->>API: signs in
    EOT
      }

      diagram "The network" {
        kind = "d2"
        text = <<EOT
    shape: rectangle
    EOT
      }

      zone "app" {
        kind    = "private"
        network = "vpc"

        component "api" {
          technology = "aws-ec2"
          data       = "confidential"
        }

        component "ledger" {
          technology = "aws-rds"
          data       = "restricted"
        }
      }

      component "browser" {
        technology = "actor-user"
      }

      user "alice" {
        name         = "Alice"
        role         = "Operator"
        access       = "admin"
        threat_actor = "insider"
        clearance    = "sc"

        uses "browser" {
          reaches = ["api"]
        }
      }

      adversary "mallory" {
        name    = "Mallory"
        reaches = ["api"]
      }

      flow browser -> api
      flow alice -> ledger {
        kind = "human"
      }
      flow mallory -> api
    }

    """

    private let trees = """
    attack_trees for "Payments" {
      tree "read-the-ledger" {
        name           = "Read the ledger"
        description    = "An operator walks one step to the table."
        raises_risk_by = 40

        goal "misconfiguration" on component "ledger"

        step "credential-theft" on component "api"
      }
    }

    """

    private func imported() {
        let answer = app.importArchitecture()
            .execute(ImportArchitectureRequest(text: payments, attackTreeText: trees))
        guard case .imported = answer else {
            Issue.record("the sample model did not import: \(answer)")
            return
        }
    }

    private func exportedJson() throws -> [String: Any] {
        imported()
        let json = app.exportModelAsJson().execute(ExportModelAsJsonRequest()).json
        return try #require(
            try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
    }

    @Test func theJsonCarriesTheUsersTheAdversariesTheActorsTheTreesAndTheDiagrams() throws {
        let json = try exportedJson()

        let users = try #require(json["users"] as? [[String: Any]])
        let alice = try #require(users.first { $0["name"] as? String == "Alice" })
        #expect(alice["role"] as? String == "Operator")
        #expect(alice["isAdversary"] as? Bool == false)
        #expect(alice["threatActorName"] as? String == "Disgruntled operator")
        #expect(alice["clearance"] as? String == "Security Check")
        let clients = try #require(alice["clients"] as? [[String: Any]])
        #expect(clients.first?["reaches"] as? [String] == ["EC2"])

        let mallory = try #require(users.first { $0["name"] as? String == "Mallory" })
        #expect(mallory["isAdversary"] as? Bool == true)
        #expect(mallory["reaches"] as? [String] == ["EC2"])

        let actors = try #require(json["threatActors"] as? [[String: Any]])
        #expect(actors.contains { $0["name"] as? String == "Disgruntled operator" })

        let attackTrees = try #require(json["attackTrees"] as? [[String: Any]])
        let tree = try #require(attackTrees.first)
        #expect(tree["name"] as? String == "Read the ledger")
        #expect(tree["raisesRiskBy"] as? Int == 40)
        let steps = try #require(tree["steps"] as? [[String: Any]])
        #expect(steps.contains { $0["threatName"] as? String == "Credential Theft" })

        let diagrams = try #require(json["diagrams"] as? [[String: Any]])
        #expect(diagrams.contains { $0["kind"] as? String == "mermaid" })
        #expect(diagrams.contains { $0["kind"] as? String == "d2" })
    }

    @Test func theJsonThreatCarriesTheDecisionTheTreeTheAssumptionScoreAndTheLibrary() throws {
        let threat = ReportThreat(
            threatId: "credential-theft",
            name: "Credential Theft",
            description: "An attacker steals a credential.",
            severityLabel: "High",
            riskScore: 9,
            riskLevel: "high",
            strideLabels: ["Spoofing"],
            mitreTechniqueIds: [],
            raisedByTree: "Read the ledger",
            overriddenBy: "acme",
            sourceName: "EC2",
            sourceKind: "Component",
            sourceId: "component:api",
            controls: [],
            pathwayMitigationLabels: [],
            scoreIfAssumptionsHold: 4,
            severityDecision: ReportSeverityDecision(
                fromLabel: "Medium",
                toLabel: "High",
                rationale: "The exploit reads the whole table.",
                sources: ["https://example.test/decision"]
            )
        )
        let json = try Self.exported(threat: threat)

        let threats = try #require(json["threats"] as? [[String: Any]])
        let written = try #require(threats.first)
        #expect(written["raisedByTree"] as? String == "Read the ledger")
        #expect(written["overriddenBy"] as? String == "acme")
        #expect(written["scoreIfAssumptionsHold"] as? Int == 4)

        let decision = try #require(written["severityDecision"] as? [String: Any])
        #expect(decision["from"] as? String == "Medium")
        #expect(decision["to"] as? String == "High")
        #expect(decision["rationale"] as? String == "The exploit reads the whole table.")
        #expect(decision["sources"] as? [String] == ["https://example.test/decision"])
    }

    /// The acceptance test: one model holding a user, an adversary, an attack
    /// tree and a diagram. The JSON matches the published schema and states
    /// all four, and neither the OTM file nor the threatcl file points a flow
    /// at an element it does not declare.
    @Test func theExportsStateTheUserTheAdversaryTheTreeAndTheDiagram() throws {
        let json = try exportedJson()

        #expect(Self.faults(in: json).isEmpty, "\(Self.faults(in: json))")

        let users = try #require(json["users"] as? [[String: Any]])
        #expect(users.contains { $0["name"] as? String == "Alice" })
        #expect(users.contains { $0["isAdversary"] as? Bool == true })
        #expect((json["attackTrees"] as? [[String: Any]])?.isEmpty == false)
        #expect((json["diagrams"] as? [[String: Any]])?.isEmpty == false)

        let otmText = app.exportModelAsOtm().execute(ExportModelAsOtmRequest()).json
        let otm = try #require(
            try JSONSerialization.jsonObject(with: Data(otmText.utf8)) as? [String: Any]
        )
        let declared = Set(
            try #require(otm["components"] as? [[String: Any]]).compactMap { $0["id"] as? String }
        )
        let dataflows = try #require(otm["dataflows"] as? [[String: Any]])
        #expect(dataflows.isEmpty == false)
        for flow in dataflows {
            let source = try #require(flow["source"] as? String)
            let destination = try #require(flow["destination"] as? String)
            #expect(declared.contains(source), "no OTM component declares \(source)")
            #expect(declared.contains(destination), "no OTM component declares \(destination)")
        }

        let hcl = app.exportModelAsThreatcl().execute(ExportModelAsThreatclRequest()).hcl
        for (from, to) in Self.flows(in: hcl) {
            #expect(Self.elements(in: hcl).contains(from), "the threatcl file declares no \(from)")
            #expect(Self.elements(in: hcl).contains(to), "the threatcl file declares no \(to)")
        }
    }

    /// The exported JSON, for one report holding one threat.
    private static func exported(threat: ReportThreat) throws -> [String: Any] {
        let report = Report(
            modelName: "Payments",
            catalogueTag: "v1.0.0",
            summary: ReportSummary(
                totalThreats: 1,
                byLevel: [],
                byStride: [],
                controlsOffered: 0,
                controlsRecorded: 0
            ),
            components: [],
            connections: [],
            zones: [],
            threats: [threat]
        )
        let json = ExportModelAsJson(reports: FixedReport(report: report))
            .execute(ExportModelAsJsonRequest())
            .json
        return try #require(
            try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]
        )
    }

    /// Every way the written file departs from
    /// `docs/threatmodel-export.schema.json`.
    private static func faults(in json: [String: Any]) -> [String] {
        (try? JsonSchemaCheck.faults(in: json, against: JsonSchemaCheck.exportSchema()))
            ?? ["the schema did not load"]
    }

    /// Every `from` and `to` pair the threatcl flows state.
    private static func flows(in hcl: String) -> [(String, String)] {
        var pairs: [(String, String)] = []
        var from: String?
        for line in hcl.split(separator: "\n", omittingEmptySubsequences: false) {
            let text = line.trimmingCharacters(in: .whitespaces)
            if text.hasPrefix("from = ") { from = Self.quoted(after: "from = ", in: text) }
            if text.hasPrefix("to = "), let source = from {
                if let target = Self.quoted(after: "to = ", in: text) {
                    pairs.append((source, target))
                }
                from = nil
            }
        }
        return pairs
    }

    /// Every element the threatcl data-flow diagram declares, by name.
    private static func elements(in hcl: String) -> Set<String> {
        var names: Set<String> = []
        for line in hcl.split(separator: "\n", omittingEmptySubsequences: false) {
            let text = line.trimmingCharacters(in: .whitespaces)
            for word in ["process ", "data_store ", "external_element "] where text.hasPrefix(word) {
                if let name = Self.quoted(after: word, in: text) { names.insert(name) }
            }
        }
        return names
    }

    private static func quoted(after prefix: String, in line: String) -> String? {
        let rest = line.dropFirst(prefix.count)
        guard rest.hasPrefix("\"") else { return nil }
        let body = rest.dropFirst()
        guard let end = body.firstIndex(of: "\"") else { return nil }
        return String(body[body.startIndex..<end])
    }
}

/// A report gateway that gives back one report a test wrote.
private struct FixedReport: BuildThreatModelReportUseCase {
    let report: Report

    func execute(_ request: BuildThreatModelReportRequest) -> BuildThreatModelReportResponse {
        BuildThreatModelReportResponse(report: report)
    }
}
