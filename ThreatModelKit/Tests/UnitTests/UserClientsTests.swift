import ArchitectureDSL
import FileGateways
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// A user reaches the system through the clients it holds: the `uses` list
/// on the user block. The design in
/// `docs/superpowers/specs/2026-09-18-user-through-a-client-design.md`
/// states the rules these tests read.
@Suite("A user through a client")
struct UserClientsTests {
    private let app = TestDependencies()
    private let architecture = HclArchitectureSource()

    private static let golden = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Goldens")
        .appendingPathComponent("user-clients.arch")

    /// Alice, an insider, holds a browser and a mobile app. The browser
    /// reaches the api and the console; the mobile app reaches the api. The
    /// batch component is reached by nothing Alice holds.
    private let payments = """
    system "Payments" {
      threat_actor "insider" {
        name       = "Disgruntled operator"
        capability = "targeted"
        intent     = "sabotage"
        performs   = ["credential-theft", "connection-mitm"]
      }

      technology "web" {
        name     = "Web Browser"
        category = "client"
      }

      technology "app" {
        name     = "Mobile App"
        category = "client"
      }

      component "api" {
        technology = "aws-ec2"
        name       = "API"
        data       = "confidential"
      }

      component "console" {
        technology = "aws-ec2"
        name       = "Admin console"
        data       = "confidential"
      }

      component "batch" {
        technology = "aws-ec2"
        name       = "Batch"
        data       = "confidential"
      }

      component "browser" {
        technology = "web"
      }

      component "mobile" {
        technology = "app"
      }

      user "alice" {
        name         = "Alice"
        role         = "Operator"
        access       = "admin"
        uses         = ["browser", "mobile"]
        threat_actor = "insider"
      }

      flow browser -> api
      flow browser -> console
      flow mobile -> api
    }

    """

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    private func threat(_ id: String, on sourceId: String) throws -> AssessedThreat {
        try #require(threats().first { $0.threatId == id && $0.source.id == sourceId })
    }

    // MARK: the language

    @Test func theParserReadsTheClientsAUserHolds() throws {
        let source = try #require(architecture.read(payments).source)

        let alice = try #require(source.users.first)
        #expect(alice.uses == ["browser", "mobile"])
        #expect(alice.reaches == [])
    }

    @Test func theGoldenFileRoundTripsByteForByte() throws {
        let golden = try String(contentsOf: Self.golden, encoding: .utf8)
        let source = try #require(architecture.read(golden).source)

        #expect(architecture.write(source) == golden)
    }

    @Test func aWrittenFileReadsBackTheSame() throws {
        let source = try #require(architecture.read(payments).source)

        #expect(architecture.write(source) == payments)
    }

    @Test func theWriterSortsTheClientsIntoDeclarationOrder() throws {
        let source = try #require(
            architecture.read(
                """
                system "Payments" {
                  component "browser" {
                    technology = "actor-browser"
                  }

                  component "mobile" {
                    technology = "actor-mobile"
                  }

                  user "alice" {
                    uses = ["mobile", "browser"]
                  }
                }

                """
            ).source
        )

        #expect(architecture.write(source).contains("uses = [\"browser\", \"mobile\"]"))
    }

    @Test func aUseNamingNoComponentIsAnError() {
        let read = architecture.read(
            """
            system "Payments" {
              user "alice" {
                uses = ["ghost"]
              }
            }

            """
        )

        #expect(read.hasErrors)
        #expect(
            read.diagnostics.contains {
                $0.message == "the user \"alice\" uses \"ghost\", which this file does not declare"
            }
        )
    }

    @Test func aUserHoldsNoUser() {
        let read = architecture.read(
            """
            system "Payments" {
              user "alice" {
                uses = ["bob"]
              }

              user "bob" {
              }
            }

            """
        )

        #expect(
            read.diagnostics.contains {
                $0.message == "the user \"alice\" uses \"bob\", which this file does not declare"
            }
        )
    }

    @Test func anEntryTheBlockDoesNotHoldNamesUses() {
        let read = architecture.read(
            """
            system "Payments" {
              user "alice" {
                via = "browser"
              }
            }

            """
        )

        #expect(
            read.diagnostics.contains {
                $0.message == "a user holds name, role, access, uses, reaches and threat_actor, "
                    + "not \"via\""
            }
        )
    }

    @Test func theMergeRefusesAUseNoFileDeclares() {
        let read = architecture.read(
            [
                SourcePart(file: "arch/payments.arch", text: "system \"Payments\" { }\n"),
                SourcePart(
                    file: "arch/people.arch",
                    text: "user \"alice\" {\n  uses = [\"ghost\"]\n}\n"
                )
            ],
            named: "Payments"
        )

        #expect(
            read.diagnostics.contains {
                $0.message == "the user \"alice\" uses \"ghost\", which this system does not declare"
            }
        )
    }

    @Test func aUserInAPartFileHoldsAClientAnotherFileDeclares() throws {
        let read = architecture.read(
            [
                SourcePart(file: "arch/payments.arch", text: "system \"Payments\" { }\n"),
                SourcePart(
                    file: "arch/edge.arch",
                    text: "component \"browser\" {\n  technology = \"actor-browser\"\n}\n"
                ),
                SourcePart(
                    file: "arch/people.arch",
                    text: "user \"alice\" {\n  uses = [\"browser\"]\n}\n"
                )
            ],
            named: "Payments"
        )

        #expect(read.hasErrors == false)
        #expect(read.source?.users.first?.uses == ["browser"])
    }

    // MARK: the model

    @Test func theModelDrawsAUseLinkFromTheUserToEachClientAndNoneToATarget() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())

        let alice = view.components.first { $0.id == "alice" }
        #expect(alice?.uses == ["browser", "mobile"])
        let uses = view.connections.filter(\.isUse)
        #expect(uses.map(\.id) == ["use:alice:browser", "use:alice:mobile"])
        #expect(uses.map(\.sourceComponentId) == ["alice", "alice"])
        #expect(uses.map(\.targetComponentId) == ["browser", "mobile"])
        #expect(uses.map(\.kindId) == ["human", "human"])
        #expect(view.connections.filter { $0.isUse == false }.map(\.id)
            == ["browser->api", "browser->console", "mobile->api"])
        #expect(view.connections.contains { $0.sourceComponentId == "alice" && $0.isUse == false } == false)
        #expect(view.components.filter { $0.id == "alice" }.count == 1)
        #expect(view.components.filter { $0.id == "browser" }.count == 1)
    }

    @Test func aUseLinkRaisesNoThreatAndIsNotWrittenAsAFlow() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        #expect(threats().contains { $0.source.id.hasPrefix("connection:use:") } == false)
        let written = app.exportArchitecture().execute(ExportArchitectureRequest()).text
        #expect(written.contains("flow alice") == false)
        #expect(written.contains("uses         = [\"browser\", \"mobile\"]"))
    }

    // MARK: the score

    /// Section 5 of the design: the actor a user names performs on the
    /// clients the user holds, on the flows that leave them and on what
    /// those flows reach, and not beyond.
    @Test func theUsersActorPerformsOnTheClientsPathAndNotBeyond() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let onApi = try threat("credential-theft", on: "component:api")
        #expect(onApi.likelihoodId == "targeted")
        #expect(onApi.likelihoodReason == "set by Disgruntled operator")
        #expect(onApi.performedByLabels == ["Disgruntled operator"])

        let onConsole = try threat("credential-theft", on: "component:console")
        #expect(onConsole.likelihoodId == "targeted")

        let onTheFlow = try threat("connection-mitm", on: "connection:browser->api")
        #expect(onTheFlow.likelihoodReason == "set by Disgruntled operator")
        #expect(onTheFlow.performedByLabels == ["Disgruntled operator"])

        let onBatch = try threat("credential-theft", on: "component:batch")
        #expect(onBatch.likelihoodId == "commodity")
        #expect(onBatch.likelihoodReason == "from the catalogue")
        #expect(onBatch.performedByLabels.isEmpty)

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
        #expect(report.threatActors.map(\.name) == ["Disgruntled operator"])
    }

    @Test func anActorTheSystemFacesPerformsEverywhereWhateverAUserHolds() throws {
        let faced = payments.replacingOccurrences(
            of: "system \"Payments\" {\n",
            with: "system \"Payments\" {\n  faces = [\"insider\"]\n"
        )
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: faced))

        let onBatch = try threat("credential-theft", on: "component:batch")
        #expect(onBatch.likelihoodId == "targeted")
    }

    // MARK: the report

    @Test func theScopeLineNamesTheUserTheClientAndTheTarget() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(report.users == [
            ReportUser(
                name: "Alice",
                role: "Operator",
                accessLabel: "Administrator",
                clients: [
                    ReportClient(name: "Web Browser", reaches: ["API", "Admin console"]),
                    ReportClient(name: "Mobile App", reaches: ["API"])
                ],
                threatActorName: "Disgruntled operator"
            )
        ])
        #expect(
            markdown.contains(
                "- Alice (Operator, Administrator): through Web Browser reaches API and "
                    + "Admin console; through Mobile App reaches API; "
                    + "is the threat actor Disgruntled operator"
            )
        )
    }

    @Test func theScopeLineReadsEachShapeOfClient() {
        #expect(
            MarkdownScope.line(
                for: ReportUser(
                    name: "Bob",
                    role: "Customer",
                    accessLabel: "User",
                    reaches: ["Ledger"],
                    clients: [ReportClient(name: "Web Browser", reaches: [])]
                )
            ) == "Bob (Customer, User): reaches Ledger; through Web Browser reaches nothing"
        )
        #expect(
            MarkdownScope.line(for: ReportUser(name: "Carol", accessLabel: "User"))
                == "Carol (User): reaches nothing"
        )
    }

    // MARK: the window's use cases

    @Test func settingTheUsersClientsWritesThem() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let answer = app.setUserProperties().execute(
            SetUserPropertiesRequest(
                componentId: "alice",
                name: "Alice",
                role: "Operator",
                access: "admin",
                uses: ["mobile"],
                reaches: [],
                threatActorId: "insider"
            )
        )

        #expect(answer == .updated)
        let written = app.exportArchitecture().execute(ExportArchitectureRequest()).text
        #expect(written.contains("uses         = [\"mobile\"]"))
        #expect(written.contains("browser\", \"mobile") == false)
    }

    @Test func theUseCaseRefusesAClientTheParserRefuses() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        _ = app.addUser().execute(AddUserRequest(x: 0, y: 0))
        let bob = app.viewThreatModel().execute(ViewThreatModelRequest()).components
            .first { $0.isUser && $0.id != "alice" }?.id ?? ""

        let namesAUser = app.setUserProperties().execute(
            SetUserPropertiesRequest(
                componentId: "alice", name: nil, role: "", access: "user",
                uses: [bob], reaches: [], threatActorId: nil
            )
        )
        let namesNothing = app.setUserProperties().execute(
            SetUserPropertiesRequest(
                componentId: "alice", name: nil, role: "", access: "user",
                uses: ["ghost"], reaches: [], threatActorId: nil
            )
        )

        #expect(namesAUser == .unknownComponent(bob))
        #expect(namesNothing == .unknownComponent("ghost"))
    }

    @Test func removingAClientTakesItOffEveryUsersClients() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        _ = app.removeComponents().execute(RemoveComponentsRequest(componentIds: ["browser"]))

        let alice = app.viewThreatModel().execute(ViewThreatModelRequest()).components
            .first { $0.id == "alice" }
        #expect(alice?.uses == ["mobile"])
        let written = app.exportArchitecture().execute(ExportArchitectureRequest()).text
        #expect(written.contains("uses         = [\"mobile\"]"))
    }

    @Test func aSavedDocumentKeepsTheClients() throws {
        let model = ThreatModel(
            name: "Payments",
            components: [
                Component(
                    id: ComponentId("alice"),
                    technologyId: Component.userTechnologyId,
                    position: Point(x: 10, y: 20),
                    sensitivity: .internalData,
                    customName: "Alice",
                    statesOwnSensitivity: false,
                    user: UserFacts(role: "Operator", uses: ["browser"], reaches: ["api"])
                )
            ]
        )
        let codec = ThreatModelCodec()

        let read = try codec.decode(try codec.encode(model))

        #expect(read.components == model.components)
    }
}
