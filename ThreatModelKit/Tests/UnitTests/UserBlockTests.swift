import ArchitectureDSL
import FileGateways
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// The `user` block: a human with a role, an access level, the components
/// the user reaches, and the threat actor the user is. The user block design
/// states it.
@Suite("The user block")
struct UserBlockTests {
    private let app = TestDependencies()
    private let architecture = HclArchitectureSource()

    private static let golden = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Goldens")
        .appendingPathComponent("users.arch")

    private func goldenText() throws -> String {
        try String(contentsOf: Self.golden, encoding: .utf8)
    }

    private let insider = """
    system "Payments" {
      threat_actor "insider" {
        name       = "Disgruntled operator"
        capability = "targeted"
        intent     = "sabotage"
        performs   = ["credential-theft"]
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      user "alice" {
        name         = "Alice"
        role         = "Operator"
        access       = "admin"
        reaches      = ["api"]
        threat_actor = "insider"
      }

      flow alice -> api
    }

    """

    private let faced = """
    system "Payments" {
      faces = ["insider"]

      threat_actor "insider" {
        name       = "Disgruntled operator"
        capability = "targeted"
        intent     = "sabotage"
        performs   = ["credential-theft"]
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    // MARK: the language

    @Test func theParserReadsAUserBlock() throws {
        let source = try #require(architecture.read(insider).source)

        #expect(source.users == [
            SourceUser(
                id: "alice",
                name: "Alice",
                role: "Operator",
                access: "admin",
                reaches: ["api"],
                threatActorId: "insider"
            )
        ])
        #expect(source.everyComponent.map(\.id) == ["api"])
    }

    @Test func aUserThatStatesNothingTakesTheDefaults() throws {
        let source = try #require(
            architecture.read(
                """
                system "Payments" {
                  user "carol" {
                  }
                }

                """
            ).source
        )

        #expect(source.users == [SourceUser(id: "carol")])
        #expect(source.users[0].access == "user")
    }

    @Test func theGoldenFileRoundTripsByteForByte() throws {
        let golden = try goldenText()
        let source = try #require(architecture.read(golden).source)

        #expect(architecture.write(source) == golden)
    }

    @Test func aWrittenUserReadsBackTheSame() throws {
        let source = try #require(architecture.read(insider).source)

        let again = try #require(architecture.read(architecture.write(source)).source)

        #expect(again.users == source.users)
        #expect(again.flows == source.flows)
        #expect(architecture.write(source) == insider)
    }

    @Test func anAccessWordOutsideTheVocabularyIsAnError() {
        let read = architecture.read(
            """
            system "Payments" {
              user "alice" {
                access = "god"
              }
            }

            """
        )

        #expect(read.hasErrors)
        #expect(
            read.diagnostics.contains {
                $0.message == "access is \"god\"; this application holds \"admin\", \"kernel\", "
                    + "\"root\", \"system\", \"user\""
            }
        )
    }

    @Test func anEntryTheBlockDoesNotHoldIsAnError() {
        let read = architecture.read(
            """
            system "Payments" {
              user "alice" {
                technology = "aws-ec2"
              }
            }

            """
        )

        #expect(
            read.diagnostics.contains {
                $0.message == "a user holds name, role, access, uses, reaches and threat_actor, "
                    + "not \"technology\""
            }
        )
    }

    @Test func aReachNamingNoComponentIsAnError() {
        let read = architecture.read(
            """
            system "Payments" {
              user "alice" {
                reaches = ["ghost"]
              }
            }

            """
        )

        #expect(read.hasErrors)
        #expect(
            read.diagnostics.contains {
                $0.message == "the user \"alice\" reaches \"ghost\", which this file does not declare"
            }
        )
    }

    @Test func aUserDeclaredTwiceIsAnError() {
        let read = architecture.read(
            """
            system "Payments" {
              user "alice" {
              }

              user "alice" {
              }
            }

            """
        )

        #expect(read.diagnostics.contains { $0.message == "the user \"alice\" is declared twice" })
    }

    @Test func aUserAndAComponentShareOneNamespace() {
        let read = architecture.read(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
              }

              user "api" {
              }
            }

            """
        )

        #expect(
            read.diagnostics.contains {
                $0.message == "\"api\" is declared as a component and as a user"
            }
        )
    }

    @Test func aFlowNamesAUserAtEitherEnd() throws {
        let source = try #require(
            architecture.read(
                """
                system "Payments" {
                  component "api" {
                    technology = "aws-ec2"
                  }

                  user "alice" {
                  }

                  flow alice -> api
                  flow api -> alice
                }

                """
            ).source
        )

        #expect(source.flows.map(\.id) == ["alice->api", "api->alice"])
    }

    @Test func aUserInAPartFileReachesAComponentAnotherFileDeclares() throws {
        let read = architecture.read(
            [
                SourcePart(file: "arch/payments.arch", text: "system \"Payments\" { }\n"),
                SourcePart(
                    file: "arch/ledger.arch",
                    text: """
                    component "api" {
                      technology = "aws-ec2"
                    }

                    """
                ),
                SourcePart(
                    file: "arch/people.arch",
                    text: """
                    user "alice" {
                      reaches = ["api"]
                    }

                    flow alice -> api

                    """
                )
            ],
            named: "Payments"
        )

        let source = try #require(read.source)
        #expect(read.hasErrors == false)
        #expect(source.users.map(\.id) == ["alice"])
        #expect(read.origins[.user("alice")] == "arch/people.arch")
    }

    @Test func theMergeRefusesAReachNoFileDeclares() {
        let read = architecture.read(
            [
                SourcePart(file: "arch/payments.arch", text: "system \"Payments\" { }\n"),
                SourcePart(
                    file: "arch/people.arch",
                    text: "user \"alice\" {\n  reaches = [\"ghost\"]\n}\n"
                )
            ],
            named: "Payments"
        )

        #expect(
            read.diagnostics.contains {
                $0.message == "the user \"alice\" reaches \"ghost\", which this system does not declare"
            }
        )
    }

    @Test func aSplitSystemWritesEachUserBackIntoItsOwnFile() throws {
        let people = "user \"alice\" {\n  reaches = [\"api\"]\n}\n"
        let header = "system \"Payments\" {\n}\n"
        app.project.put(header, at: "/work/threatmodel/payments/arch/payments.arch")
        app.project.put(
            "component \"api\" {\n  technology = \"aws-ec2\"\n}\n",
            at: "/work/threatmodel/payments/arch/ledger.arch"
        )
        app.project.put(people, at: "/work/threatmodel/payments/arch/people.arch")
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        let response = app.saveSystem().execute(
            SaveSystemRequest(root: "/work", systemName: "payments")
        )

        #expect(response == .saved(architecturePath: "/work/threatmodel/payments/arch/payments.arch"))
        #expect(app.project.text(at: "/work/threatmodel/payments/arch/people.arch") == people)
        #expect(app.project.text(at: "/work/threatmodel/payments/arch/payments.arch") == header)
    }

    // MARK: existing files

    @Test func aFileWithActorTechnologiesReadsAndWritesUnchanged() throws {
        let people = """
        system "Payments" {
          component "api" {
            technology = "aws-ec2"
          }

          component "customer" {
            technology = "actor-user"
          }

          flow customer -> api
        }

        """
        let source = try #require(architecture.read(people).source)

        #expect(source.users.isEmpty)
        #expect(source.everyComponent.map(\.technologyId) == ["aws-ec2", "actor-user"])
        #expect(architecture.write(source) == people)

        let response = app.importArchitecture().execute(ImportArchitectureRequest(text: people))
        guard case .imported(_, let warnings, _) = response else {
            Issue.record("the import refused the file: \(response)")
            return
        }
        #expect(warnings.isEmpty)
        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.first { $0.id == "customer" }?.isUser == false)
        #expect(view.components.first { $0.id == "customer" }?.shapeId == "actor")
    }

    // MARK: the model

    @Test func theModelDrawsAUserWithTheActorShape() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: insider))

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        let alice = view.components.first { $0.id == "alice" }

        #expect(alice?.isUser == true)
        #expect(alice?.shapeId == "actor")
        #expect(alice?.name == "Alice")
        #expect(alice?.role == "Operator")
        #expect(alice?.runsAsId == "admin")
        #expect(alice?.reaches == ["api"])
        #expect(alice?.threatActorId == "insider")
        #expect(alice?.isUnknownTechnology == false)
        #expect(view.connections.map(\.id) == ["alice->api"])
    }

    @Test func aUserRaisesNoThreats() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: insider))

        let threats = app.assessThreatModel().execute(AssessThreatModelRequest()).threats

        #expect(threats.contains { $0.source.id == "component:alice" } == false)
        #expect(threats.contains { $0.source.id == "component:api" })
    }

    @Test func aUserNamingAnActorNoBlockDeclaresIsRefused() {
        let response = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  user "alice" {
                    threat_actor = "ghost"
                  }
                }

                """
            )
        )

        guard case .refused(let diagnostics) = response else {
            Issue.record("the import took a user naming an actor nothing declares")
            return
        }
        #expect(
            diagnostics.map(\.message) == [
                "the user \"alice\" names the threat actor \"ghost\", which no threat_actor block declares"
            ]
        )
    }

    @Test func aUserNamingTheBuiltInActorOpens() {
        let response = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  user "mallory" {
                    threat_actor = "commodity-crimeware"
                  }
                }

                """
            )
        )

        guard case .imported = response else {
            Issue.record("the import refused the built-in actor: \(response)")
            return
        }
    }

    /// The insider is a user with a `threat_actor`. The assessment faces the
    /// actor the way it faces one `faces` lists: credential theft takes the
    /// insider's targeted tier, and the report names the insider.
    @Test func anInsiderUserIsFacedAsAnActor() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: insider))
        let listed = TestDependencies()
        _ = listed.importArchitecture().execute(ImportArchitectureRequest(text: faced))

        let byUser = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.threatId == "credential-theft" }
        )
        let byFaces = try #require(
            listed.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.threatId == "credential-theft" }
        )

        #expect(byUser.likelihoodId == "targeted")
        #expect(byUser.likelihoodReason == "set by Disgruntled operator")
        #expect(byUser.performedByLabels == ["Disgruntled operator"])
        #expect(byUser.riskScore == byFaces.riskScore)
        #expect(byUser.likelihoodId == byFaces.likelihoodId)

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
        #expect(report.threatActors.map(\.name) == ["Disgruntled operator"])
    }

    @Test func aModelWithNoUserScoresWhatItScoredBefore() throws {
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  component "api" {
                    technology = "aws-ec2"
                    data       = "confidential"
                  }
                }

                """
            )
        )

        let theft = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.threatId == "credential-theft" }
        )

        #expect(theft.likelihoodId == "commodity")
        #expect(theft.likelihoodReason == "from the catalogue")
    }

    @Test func theActorsInUseShowTheUsersActorAsFaced() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: insider))

        let actors = app.listThreatActorsInUse().execute(ListThreatActorsInUseRequest()).actors

        #expect(try #require(actors.first { $0.id == "insider" }).isFaced)
    }

    @Test func aWrittenFileHoldsTheUserBlock() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: insider))

        let written = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(written == insider)
    }

    @Test func aSavedDocumentKeepsTheUserFacts() throws {
        let model = ThreatModel(
            name: "Payments",
            components: [
                Component(
                    id: ComponentId("alice"),
                    technologyId: Component.userTechnologyId,
                    position: Point(x: 10, y: 20),
                    sensitivity: .internalData,
                    customName: "Alice",
                    runsAs: .admin,
                    statesOwnSensitivity: false,
                    user: UserFacts(role: "Operator", reaches: ["api"], threatActorId: "insider")
                )
            ]
        )
        let codec = ThreatModelCodec()

        let read = try codec.decode(try codec.encode(model))

        #expect(read.components == model.components)
    }

    // MARK: the window's use cases

    @Test func addingAUserWritesAUserBlockAndNoComponentBlock() {
        let response = app.addUser().execute(AddUserRequest(x: 40, y: 50))

        guard case .added(let id) = response else {
            Issue.record("the user was not added")
            return
        }
        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        let user = view.components.first { $0.id == id }
        #expect(user?.isUser == true)
        #expect(user?.name == "User")
        #expect(user?.shapeId == "actor")
        #expect(user?.x == 40)

        let written = app.exportArchitecture().execute(ExportArchitectureRequest()).text
        #expect(written.contains("user \"\(id)\" {"))
        #expect(written.contains("name = \"User\""))
        #expect(written.contains("component \"") == false)
    }

    @Test func settingTheUsersPropertiesWritesThem() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: insider))
        _ = app.addUser().execute(AddUserRequest(x: 0, y: 0))
        let added = try #require(
            app.viewThreatModel().execute(ViewThreatModelRequest()).components
                .first { $0.isUser && $0.id != "alice" }
        )

        let answer = app.setUserProperties().execute(
            SetUserPropertiesRequest(
                componentId: added.id,
                name: "Bob",
                role: "Customer",
                access: "user",
                reaches: ["api"],
                threatActorId: nil
            )
        )

        #expect(answer == .updated)
        let bob = try #require(
            app.viewThreatModel().execute(ViewThreatModelRequest()).components
                .first { $0.id == added.id }
        )
        #expect(bob.name == "Bob")
        #expect(bob.role == "Customer")
        #expect(bob.reaches == ["api"])
        #expect(bob.threatActorId == nil)
    }

    @Test func settingTheUsersActorFacesIt() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: insider))
        _ = app.setUserProperties().execute(
            SetUserPropertiesRequest(
                componentId: "alice",
                name: "Alice",
                role: "Operator",
                access: "admin",
                reaches: ["api"],
                threatActorId: nil
            )
        )
        let unfaced = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.threatId == "credential-theft" }
        )
        #expect(unfaced.likelihoodId == "commodity")

        let answer = app.setUserProperties().execute(
            SetUserPropertiesRequest(
                componentId: "alice",
                name: "Alice",
                role: "Operator",
                access: "admin",
                reaches: ["api"],
                threatActorId: "insider"
            )
        )

        #expect(answer == .updated)
        let faced = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.threatId == "credential-theft" }
        )
        #expect(faced.likelihoodId == "targeted")
    }

    @Test func theUseCaseRefusesWhatTheParserRefuses() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: insider))

        func set(access: String = "admin", reaches: [String] = ["api"], actor: String? = nil)
            -> SetUserPropertiesResponse {
            app.setUserProperties().execute(
                SetUserPropertiesRequest(
                    componentId: "alice",
                    name: "Alice",
                    role: "",
                    access: access,
                    reaches: reaches,
                    threatActorId: actor
                )
            )
        }

        #expect(set(access: "god") == .unknownAccessLevel)
        #expect(set(reaches: ["ghost"]) == .unknownComponent("ghost"))
        #expect(set(reaches: ["alice"]) == .unknownComponent("alice"))
        #expect(set(actor: "ghost") == .unknownActor("ghost"))
        #expect(
            app.setUserProperties().execute(
                SetUserPropertiesRequest(
                    componentId: "api",
                    name: nil,
                    role: "",
                    access: "user",
                    reaches: [],
                    threatActorId: nil
                )
            ) == .unknownUser
        )
    }

    @Test func removingAComponentTakesItOffEveryUsersReaches() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: insider))

        _ = app.removeComponents().execute(RemoveComponentsRequest(componentIds: ["api"]))

        let alice = app.viewThreatModel().execute(ViewThreatModelRequest()).components
            .first { $0.id == "alice" }
        #expect(alice?.reaches == [])
        let written = app.exportArchitecture().execute(ExportArchitectureRequest()).text
        #expect(written.contains("reaches") == false)
    }

    @Test func aUserSitsInNoZone() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: insider))
        _ = app.addZone().execute(
            AddZoneRequest(x: -1000, y: -1000, width: 4000, height: 4000)
        )

        _ = app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: "alice", x: 0, y: 0)])
        )

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.first { $0.id == "alice" }?.zoneId == nil)
        #expect(view.components.first { $0.id == "api" }?.zoneId != nil)
    }

    // MARK: the report

    @Test func theReportListsUsersInTheScopeSection() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: insider))

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(report.users == [
            ReportUser(
                name: "Alice",
                role: "Operator",
                accessLabel: "Administrator",
                reaches: ["EC2"],
                threatActorName: "Disgruntled operator"
            )
        ])
        #expect(report.components.map(\.id) == ["api"])
        #expect(markdown.contains("## Scope"))
        #expect(markdown.contains("### Users"))
        #expect(
            markdown.contains(
                "- Alice (Operator, Administrator): reaches EC2; "
                    + "is the threat actor Disgruntled operator"
            )
        )
    }

    @Test func theScopeLineReadsEachShapeOfUser() {
        #expect(
            MarkdownScope.line(
                for: ReportUser(name: "Bob", accessLabel: "User")
            ) == "Bob (User): reaches nothing"
        )
        #expect(
            MarkdownScope.line(
                for: ReportUser(
                    name: "Bob",
                    role: "Customer",
                    accessLabel: "User",
                    reaches: ["API", "Ledger", "Vault"]
                )
            ) == "Bob (Customer, User): reaches API, Ledger and Vault"
        )
    }

    // MARK: the adversary alias

    private let phisher = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      adversary "phisher" {
        name    = "Phisher"
        role    = "Customer"
        reaches = ["api"]
      }
    }

    """

    @Test func theParserReadsAnAdversaryBlock() throws {
        let source = try #require(architecture.read(phisher).source)

        #expect(source.users == [
            SourceUser(
                id: "phisher",
                name: "Phisher",
                role: "Customer",
                reaches: ["api"],
                isAdversary: true
            )
        ])
    }

    @Test func aUserBlockReadsAsALegitimateUser() throws {
        let source = try #require(architecture.read(insider).source)

        #expect(source.users.map(\.isAdversary) == [false])
    }

    @Test func theWriterWritesAnAdversaryBackAsAnAdversary() throws {
        let source = try #require(architecture.read(phisher).source)

        #expect(architecture.write(source) == phisher)
    }

    @Test func theWriterWritesALegitimateUserAsAUser() throws {
        let source = try #require(architecture.read(insider).source)

        #expect(architecture.write(source) == insider)
    }

    @Test func anEntryTheAdversaryBlockDoesNotHoldIsAnError() {
        let read = architecture.read(
            """
            system "Payments" {
              adversary "phisher" {
                technology = "aws-ec2"
              }
            }

            """
        )

        #expect(
            read.diagnostics.contains {
                $0.message == "an adversary holds name, role, access, uses, reaches and "
                    + "threat_actor, not \"technology\""
            }
        )
    }

    @Test func savingAndOpeningKeepsTheAdversaryKeyword() throws {
        app.project.put(phisher, at: "/work/threatmodel/payments.arch")
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))

        let written = try #require(app.project.text(at: "/work/threatmodel/payments.arch"))
        #expect(written.contains("adversary \"phisher\" {"))
        #expect(written.contains("user \"phisher\" {") == false)

        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        let again = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(again.components.first { $0.id == "phisher" }?.isAdversary == true)
    }

    @Test func aSavedDocumentKeepsTheAdversaryFlag() throws {
        let model = ThreatModel(
            name: "Payments",
            components: [
                Component(
                    id: ComponentId("phisher"),
                    technologyId: Component.userTechnologyId,
                    position: Point(x: 10, y: 20),
                    sensitivity: .internalData,
                    customName: "Phisher",
                    statesOwnSensitivity: false,
                    user: UserFacts(role: "Customer", isAdversary: true)
                )
            ]
        )
        let codec = ThreatModelCodec()

        let read = try codec.decode(try codec.encode(model))

        #expect(read.components == model.components)
        #expect(read.components.first?.user?.isAdversary == true)
    }

    @Test func anAdversaryRaisesNoThreats() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: phisher))

        let threats = app.assessThreatModel().execute(AssessThreatModelRequest()).threats

        #expect(threats.contains { $0.source.id == "component:phisher" } == false)
    }

    @Test func theUseCaseWritesTheAdversaryKeyword() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: insider))

        let answer = app.setUserProperties().execute(
            SetUserPropertiesRequest(
                componentId: "alice",
                name: "Alice",
                role: "Operator",
                access: "admin",
                reaches: ["api"],
                threatActorId: "insider",
                isAdversary: true
            )
        )

        #expect(answer == .updated)
        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.first { $0.id == "alice" }?.isAdversary == true)
        let written = app.exportArchitecture().execute(ExportArchitectureRequest()).text
        #expect(written.contains("adversary \"alice\" {"))
    }

    @Test func theReportNamesTheAdversaryInTheScopeSection() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: phisher))

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(report.users.first?.isAdversary == true)
        #expect(markdown.contains("- Phisher (adversary, Customer, User): reaches EC2"))
    }

    @Test func theScopeLineNamesAnAdversary() {
        #expect(
            MarkdownScope.line(
                for: ReportUser(name: "Phisher", accessLabel: "User", isAdversary: true)
            ) == "Phisher (adversary, User): reaches nothing"
        )
    }
}
