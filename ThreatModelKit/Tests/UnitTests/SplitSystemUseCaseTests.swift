import CommandLineApplication
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// The window runs `SplitSystem` where the executable runs `split`. Both
/// divide one system into the directory form, one architecture file per zone.
@Suite("Dividing a system by zone")
struct SplitSystemUseCaseTests {
    private let payments = """
    system "Payments" {
      catalogue = "v1.0.0"

      use_case "pay" {
        text = "A customer pays."
      }

      asset "ledger-rows" {
        name           = "Ledger rows"
        classification = "restricted"
      }

      authors = ["craig"]

      zone "edge" {
        kind = "public"

        component "waf" { technology = "aws-waf" }
      }

      zone "core" {
        component "queue" { technology = "aws-sqs" }
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      flow waf -> api
      flow api -> queue
    }

    """

    private func run(_ project: InMemoryProject, _ words: String...) -> (code: Int32, lines: [String]) {
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(arguments: ["threatmodeller"] + words, output: { lines.append($0) })
        return (code, lines)
    }

    private func aFlatProject() -> TestDependencies {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        return useCases
    }

    private func split(_ useCases: TestDependencies) -> SplitSystemResponse {
        useCases.splitSystem().execute(
            SplitSystemRequest(root: "/work", systemName: "payments")
        )
    }

    // MARK: the files the split writes

    @Test func writesOneArchitectureFilePerZone() {
        let useCases = aFlatProject()

        #expect(split(useCases) == .split)
        #expect(useCases.project.text(at: "/work/threatmodel/payments/arch/payments.arch") != nil)
        #expect(useCases.project.text(at: "/work/threatmodel/payments/arch/edge.arch") != nil)
        #expect(useCases.project.text(at: "/work/threatmodel/payments/arch/core.arch") != nil)
        #expect(useCases.project.text(at: "/work/threatmodel/payments.arch") == nil)
    }

    @Test func aZoneFileHoldsItsOwnComponents() throws {
        let useCases = aFlatProject()
        _ = split(useCases)

        let edge = try #require(useCases.project.text(at: "/work/threatmodel/payments/arch/edge.arch"))
        #expect(edge.hasPrefix("zone \"edge\" {"))
        #expect(edge.contains("component \"waf\""))
        #expect(edge.contains("component \"queue\"") == false)
    }

    @Test func aComponentOutsideEveryZoneGoesInTheHeaderFile() throws {
        let useCases = aFlatProject()
        _ = split(useCases)

        let header = try #require(
            useCases.project.text(at: "/work/threatmodel/payments/arch/payments.arch")
        )
        #expect(header.contains("component \"api\""))
        #expect(header.contains("component \"waf\"") == false)
    }

    @Test func aFlowGoesInTheFileItsSourceSitsIn() throws {
        let useCases = aFlatProject()
        _ = split(useCases)

        let edge = try #require(useCases.project.text(at: "/work/threatmodel/payments/arch/edge.arch"))
        let header = try #require(
            useCases.project.text(at: "/work/threatmodel/payments/arch/payments.arch")
        )
        #expect(edge.contains("flow waf -> api"))
        #expect(header.contains("flow api -> queue"))
    }

    @Test func theHeaderFileKeepsEveryHeaderField() throws {
        let useCases = aFlatProject()
        _ = split(useCases)

        let header = try #require(
            useCases.project.text(at: "/work/threatmodel/payments/arch/payments.arch")
        )
        #expect(header.contains("catalogue = \"v1.0.0\""))
        #expect(header.contains("use_case \"pay\""))
        #expect(header.contains("asset \"ledger-rows\""))
        #expect(header.contains("craig"))
    }

    @Test func theSplitFilesOpenAsTheSameSystem() throws {
        let useCases = aFlatProject()
        _ = split(useCases)

        let response = useCases.openSystem().execute(
            OpenSystemRequest(root: "/work", systemName: "payments")
        )

        guard case .opened(let name, _, _) = response else {
            Issue.record("expected the split system to open, got \(response)")
            return
        }
        #expect(name == "Payments")
        #expect(
            useCases.modelStore.current().components.map(\.id.value).sorted()
                == ["api", "queue", "waf"]
        )
        #expect(useCases.modelStore.current().connections.count == 2)
    }

    @Test func aSecondSplitWritesTheSameBytes() throws {
        let useCases = aFlatProject()
        _ = split(useCases)
        let paths = [
            "/work/threatmodel/payments/arch/payments.arch",
            "/work/threatmodel/payments/arch/edge.arch",
            "/work/threatmodel/payments/arch/core.arch"
        ]
        let once = paths.map { useCases.project.text(at: $0) }

        #expect(split(useCases) == .split)

        #expect(paths.map { useCases.project.text(at: $0) } == once)
    }

    // MARK: the answers

    @Test func anAnswerFollowsTheElementItNames() throws {
        let useCases = aFlatProject()
        useCases.project.put(
            """
            controls for "Payments" {
              threat "credential-theft" on component "waf" {
                control "Answered for the waf" { status = "implemented" }
              }

              threat "credential-theft" on component "api" {
                control "Answered for the api" { status = "implemented" }
              }
            }

            """,
            at: "/work/threatmodel/payments.controls"
        )

        _ = split(useCases)

        let edge = try #require(
            useCases.project.text(at: "/work/threatmodel/payments/controls/edge.controls")
        )
        let header = try #require(
            useCases.project.text(at: "/work/threatmodel/payments/controls/payments.controls")
        )
        #expect(edge.contains("\"waf\""))
        #expect(edge.contains("\"api\"") == false)
        #expect(header.contains("\"api\""))
        #expect(useCases.project.text(at: "/work/threatmodel/payments.controls") == nil)
    }

    @Test func everyControlsFileOfASplitSystemOpensItsAnswers() throws {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              zone "core" {
                component "ledger" { technology = "aws-rds" }
              }

              zone "edge" {
                component "guard" { technology = "aws-waf" }
              }

              component "api" { technology = "aws-ec2" }

              flow api -> ledger
              mitigates guard -> ledger
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        _ = split(useCases)
        _ = useCases.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        let resolved = ThreatResolver(
            model: useCases.modelStore.current(),
            catalogue: useCases.catalogueInUse
        ).resolve()
        let onLedger = try #require(resolved.first { $0.source.id == "component:ledger" && $0.controls.isEmpty == false })
        let onApi = try #require(resolved.first { $0.source.id == "component:api" && $0.controls.isEmpty == false })
        func answer(_ threat: ResolvedThreat, on component: String, mitigatedBy: String = "") -> String {
            """
            controls for "Payments" {
              threat "\(threat.threat.id.value)" on component "\(component)" {
                control "\(threat.controls[0].description)" {
                  status = "implemented"
                  \(mitigatedBy)
                }
              }
            }

            """
        }
        useCases.project.put(
            answer(onLedger, on: "ledger", mitigatedBy: "mitigated_by \"guard->ledger\" { reduces_risk_by = 50 }"),
            at: "/work/threatmodel/payments/controls/core.controls"
        )
        useCases.project.put(
            answer(onApi, on: "api"),
            at: "/work/threatmodel/payments/controls/payments.controls"
        )

        _ = useCases.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        let statuses = useCases.modelStore.current().controlStatuses
        #expect(statuses[onLedger.controls[0].key] == .implemented)
        #expect(statuses[onApi.controls[0].key] == .implemented)
        #expect(
            useCases.modelStore.current().controlMitigatedBy[onLedger.controls[0].key]
                == [ControlMitigation(edgeId: "guard->ledger", reducesRiskBy: 50)]
        )
    }

    // MARK: the trees

    @Test func eachTreeTakesAFileOfItsOwn() throws {
        let useCases = aFlatProject()
        useCases.project.put(
            """
            attack_trees for "Payments" {
              tree "steal" {
                goal "credential-theft" on component "api"

                any_of {
                  step "guess-the-password" on component "api"
                }
              }

              tree "flood" {
                goal "credential-theft" on component "api"

                any_of {
                  step "send-many-requests" on component "api"
                }
              }
            }

            """,
            at: "/work/threatmodel/payments.attacktree"
        )

        _ = split(useCases)

        let steal = try #require(
            useCases.project.text(at: "/work/threatmodel/payments/attacktree/steal.attacktree")
        )
        let flood = try #require(
            useCases.project.text(at: "/work/threatmodel/payments/attacktree/flood.attacktree")
        )
        #expect(steal.contains("tree \"steal\""))
        #expect(steal.contains("tree \"flood\"") == false)
        #expect(flood.contains("tree \"flood\""))
        #expect(useCases.project.text(at: "/work/threatmodel/payments.attacktree") == nil)
    }

    // MARK: what the split refuses

    @Test func refusesASystemTheProjectDoesNotHold() {
        let useCases = aFlatProject()

        let response = useCases.splitSystem().execute(
            SplitSystemRequest(root: "/work", systemName: "ledger")
        )

        #expect(response == .noSuchSystem)
    }

    @Test func refusesASystemTheMergeRefuses() throws {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" { technology = "aws-ec2" }

              flow api -> ghost
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )

        let response = split(useCases)

        guard case .refused(let reason) = response else {
            Issue.record("expected the split to be refused, got \(response)")
            return
        }
        #expect(reason.contains("cannot be split"))
        #expect(useCases.project.text(at: "/work/threatmodel/payments.arch") != nil)
        #expect(useCases.project.text(at: "/work/threatmodel/payments/arch/payments.arch") == nil)
    }

    // MARK: the verb and the window

    /// The window's use case and the executable's verb write the same files,
    /// holding the same bytes.
    @Test func theVerbWritesWhatTheUseCaseWrites() throws {
        let verbProject = InMemoryProject(root: "/work")
        verbProject.put(payments, at: "/work/threatmodel/payments.arch")
        let verbResult = run(verbProject, "split", "payments", "/work")
        #expect(verbResult.code == 0)

        let useCases = aFlatProject()
        #expect(split(useCases) == .split)

        for path in [
            "/work/threatmodel/payments/arch/payments.arch",
            "/work/threatmodel/payments/arch/edge.arch",
            "/work/threatmodel/payments/arch/core.arch"
        ] {
            let fromTheVerb = try #require(verbProject.text(at: path))
            let fromTheWindow = try #require(useCases.project.text(at: path))
            #expect(fromTheWindow == fromTheVerb)
        }
        #expect(verbProject.text(at: "/work/threatmodel/payments.arch") == nil)
    }

    @Test func theVerbAnswersANonZeroCodeForASystemTheMergeRefuses() {
        let project = InMemoryProject(root: "/work")
        project.put(
            "system \"Payments\" {\n  flow api -> ghost\n}\n",
            at: "/work/threatmodel/payments.arch"
        )

        let result = run(project, "split", "payments", "/work")

        #expect(result.code != 0)
        #expect(result.lines.contains { $0.contains("cannot be split") })
    }

    /// The files the split writes still compile.
    @Test func aSplitSystemStillCompiles() {
        let useCases = aFlatProject()
        _ = split(useCases)

        let result = run(useCases.project, "compile", "/work")

        #expect(result.code == 0)
        #expect(
            useCases.project.text(at: "/work/threatmodel/payments/controls/payments.controls") != nil
        )
    }
}
