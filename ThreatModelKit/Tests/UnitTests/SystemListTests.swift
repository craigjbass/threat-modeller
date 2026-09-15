import CommandLineApplication
import Foundation
import Testing
import ThreatModelKit
import TestSupport

@Suite("Saying what each system holds and what it scores")
struct SystemListTests {
    private let project = InMemoryProject(root: "/work")

    private let payments = """
    system "Payments" {
      owner    = "Payments team"
      reviewed = "2026-01-15"

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

    private let ledger = """
    system "Ledger" {
      component "db" {
        technology = "aws-rds"
        data       = "restricted"
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
        project.put(ledger, at: "/work/threatmodel/ledger.arch")
    }

    @Test func writesOneRowPerSystem() {
        aProject()

        let run = self.run("list", "/work")

        #expect(run.code == 0)
        #expect(run.lines.first?.hasPrefix("NAME") == true)
        #expect(run.lines.contains { $0.contains("payments") })
        #expect(run.lines.contains { $0.contains("ledger") })
        #expect(run.lines.count == 3)
    }

    @Test func theRowStatesWhatTheSystemHolds() throws {
        aProject()

        let run = self.run("list", "/work")
        let row = try #require(run.lines.first { $0.contains("payments") })

        #expect(row.contains("Payments team"))
        #expect(row.contains("2026-01-15"))
        // Two components, one zone, one flow.
        let words = row.split(separator: " ").map(String.init).filter { $0.isEmpty == false }
        #expect(words.contains("2"))
        #expect(words.contains("1"))
    }

    @Test func narrowsAndOrdersTheColumns() throws {
        aProject()

        let run = self.run("list", "/work", "--fields", "name,threats")

        #expect(run.code == 0)
        #expect(run.lines.first == "NAME      THREATS")
        let row = try #require(run.lines.first { $0.hasPrefix("payments") })
        #expect(row.split(separator: " ").filter { $0.isEmpty == false }.count == 2)
    }

    @Test func dropsTheHeader() {
        aProject()

        let run = self.run("list", "/work", "--fields", "name", "--no-header")

        #expect(run.lines.contains("NAME") == false)
        #expect(run.lines.sorted() == ["ledger", "payments"])
    }

    /// A number sorts worst first, because a person asking for the worst
    /// reads the top.
    @Test func ordersTheRowsByOneColumn() {
        aProject()

        let run = self.run("list", "/work", "--fields", "name,worst", "--sort", "worst", "--no-header")
        let names = run.lines.map { $0.split(separator: " ").first.map(String.init) ?? "" }

        #expect(names.count == 2)
        let worst = run.lines.map { Int($0.split(separator: " ").last.map(String.init) ?? "") ?? 0 }
        #expect(worst == worst.sorted(by: >))
    }

    @Test func ordersTheRowsByAWordColumn() {
        aProject()

        let run = self.run("list", "/work", "--fields", "name", "--sort", "name", "--no-header")

        #expect(run.lines == ["ledger", "payments"])
    }

    @Test func refusesAColumnItDoesNotWrite() {
        aProject()

        let run = self.run("list", "/work", "--fields", "name,nothing")

        #expect(run.code != 0)
        #expect(run.lines.contains { $0.contains("there is no column \"nothing\"") })
    }

    @Test func writesTheRowsAsJson() throws {
        aProject()

        let run = self.run("list", "/work", "--json")

        #expect(run.code == 0)
        let text = run.lines.joined(separator: "\n")
        let rows = try #require(
            try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [[String: Any]]
        )
        #expect(rows.count == 2)
        let payments = try #require(rows.first { $0["name"] as? String == "payments" })
        #expect(payments["owner"] as? String == "Payments team")
        #expect(payments["components"] as? Int == 2)
        #expect(payments["zones"] as? Int == 1)
        #expect(payments["flows"] as? Int == 1)
        #expect((payments["threats"] as? Int ?? 0) > 0)
        #expect(payments["unanswered"] as? Int == payments["threats"] as? Int)
    }

    /// `check` is the verb that fails. A list that drops a system hides it.
    @Test func writesARowForASystemThatDoesNotParse() throws {
        aProject()
        project.put("system \"Broken\" {\n  zone \"z\" { kind = \"secret\" }\n}\n",
                    at: "/work/threatmodel/broken.arch")

        let run = self.run("list", "/work")

        #expect(run.code == 0)
        let row = try #require(run.lines.first { $0.contains("broken") })
        #expect(row.contains("unparsed"))
    }

    @Test func theJsonRowOfAnUnparsedSystemStatesNoNumber() throws {
        project.put("system \"Broken\" {\n  zone \"z\" { kind = \"secret\" }\n}\n",
                    at: "/work/threatmodel/broken.arch")

        let run = self.run("list", "/work", "--json")
        let text = run.lines.joined(separator: "\n")
        let rows = try #require(
            try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [[String: Any]]
        )

        let broken = try #require(rows.first)
        #expect(broken["name"] as? String == "broken")
        #expect(broken["owner"] as? String == "unparsed")
        #expect(broken["threats"] is NSNull)
    }

    @Test func aProjectWithNoSystemSaysSo() {
        let run = self.run("list", "/work")

        #expect(run.lines.contains { $0.contains("holds no .arch files") })
    }

    /// One resolve per system and no layout: the numbers come from the
    /// assessment, and nothing here places a component.
    @Test func readsAProjectOfManySystemsQuickly() {
        for index in 1 ... 20 {
            project.put(
                payments.replacingOccurrences(of: "Payments", with: "System \(index)"),
                at: "/work/threatmodel/system-\(index).arch"
            )
        }

        let started = Date()
        let run = self.run("list", "/work")
        let took = Date().timeIntervalSince(started)

        #expect(run.code == 0)
        #expect(run.lines.count == 21)
        #expect(took < 2.0, "20 systems took \(took) seconds")
        if ProcessInfo.processInfo.environment["THREATMODELLER_MEASURE"] == "1" {
            print("MEASURED list of 20 systems: \(took) seconds")
        }
    }
}
