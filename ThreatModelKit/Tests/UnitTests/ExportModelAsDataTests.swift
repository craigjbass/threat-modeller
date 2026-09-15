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

    @Test func standardOutputRefusesAProjectOfManySystems() {
        aProject()
        project.put(payments.replacingOccurrences(of: "Payments", with: "Ledger"),
                    at: "/work/threatmodel/ledger.arch")

        let run = self.run("export", "/work", "--format", "json", "--stdout")

        #expect(run.code != 0)
        #expect(run.lines.contains { $0.contains("more than one system") })
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
