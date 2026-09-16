import CommandLineApplication
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// The systems picker and `threatmodeller list` read one use case, so the two
/// state the same numbers about the same system.
@Suite("Listing a system agrees with the list verb")
struct ListSystemTests {
    /// `threatmodeller list --json` for this project, as a name-to-fields map.
    private func printed(_ useCases: TestDependencies) -> [String: [String: String]] {
        var lines: [String] = []
        _ = CommandLineApplication(
            projects: useCases.project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(
            arguments: [
                "threatmodeller", "list", "/work", "--fields", "name,unanswered,level", "--json"
            ],
            output: { lines.append($0) }
        )
        let json = lines.joined(separator: "\n")
        guard let data = json.data(using: .utf8),
              let rows = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return [:] }

        var byName: [String: [String: String]] = [:]
        for row in rows {
            guard let name = row["name"] as? String else { continue }
            byName[name] = [
                "unanswered": "\(row["unanswered"] ?? "")",
                "level": "\(row["level"] ?? "")"
            ]
        }
        return byName
    }

    private func aProjectWithOneUnansweredThreat() -> TestDependencies {
        let useCases = TestDependencies()
        useCases.project.put(
            """
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

            """,
            at: "/work/threatmodel/payments.arch"
        )
        return useCases
    }

    @Test func statesTheUnansweredCountAndTheWorstLevelTheVerbPrints() throws {
        let useCases = aProjectWithOneUnansweredThreat()
        let byName = printed(useCases)
        let expected = try #require(byName["payments"])

        guard case .listed(let summary) = useCases.listSystem().execute(
            ListSystemRequest(root: "/work", systemName: "payments")
        ) else {
            Issue.record("payments did not list")
            return
        }

        #expect(summary.isUnparsed == false)
        #expect("\(summary.unanswered)" == expected["unanswered"])
        #expect(summary.worstLevel == expected["level"])
        #expect(summary.unanswered > 0)
    }

    @Test func statesAnAnsweredSystemHasNoUnansweredThreats() throws {
        let useCases = aProjectWithOneUnansweredThreat()
        useCases.project.put(
            """
            controls for "Payments" {
              threat "credential-theft" on component "api" {
                control "Enforce IMDSv2 to block SSRF-based credential theft" {
                  status = "accepted"
                }

                control "Use IAM roles with minimal permissions" {
                  status = "accepted"
                }
              }
            }

            """,
            at: "/work/threatmodel/payments.controls"
        )

        guard case .listed(let before) = useCases.listSystem().execute(
            ListSystemRequest(root: "/work", systemName: "payments")
        ) else {
            Issue.record("payments did not list")
            return
        }

        let byName = printed(useCases)
        let expected = try #require(byName["payments"])
        #expect("\(before.unanswered)" == expected["unanswered"])
    }

    @Test func marksASystemWhoseFileDoesNotParse() {
        let useCases = TestDependencies()
        useCases.project.put("system \"Broken\" {", at: "/work/threatmodel/broken.arch")

        guard case .listed(let summary) = useCases.listSystem().execute(
            ListSystemRequest(root: "/work", systemName: "broken")
        ) else {
            Issue.record("broken did not list")
            return
        }

        #expect(summary.isUnparsed)
    }

    @Test func statesNoSuchSystemForANameTheProjectDoesNotHold() {
        let useCases = aProjectWithOneUnansweredThreat()

        let response = useCases.listSystem().execute(
            ListSystemRequest(root: "/work", systemName: "nothing-here")
        )

        #expect(response == .noSuchSystem)
    }
}
