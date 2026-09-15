import ArchitectureDSL
import FileGateways
import Testing
import ThreatModelKit
import TestSupport

@Suite("The named things of value a system holds")
struct SystemAssetTests {
    private let app = TestDependencies()
    private let architecture = HclArchitectureSource()

    private let payments = """
    system "Payments" {
      asset "card-numbers" {
        name           = "Card numbers"
        classification = "restricted"
        description    = "The primary account numbers customers type."
        owner          = "Payments team"
      }

      component "api" {
        technology = "aws-ec2"
        holds      = ["card-numbers"]
      }

      component "db" {
        technology = "aws-rds"
        data       = "public"
        holds      = ["card-numbers"]
      }

      flow api -> db {
        kind    = "network"
        carries = ["card-numbers"]
      }
    }

    """

    private func drawTheModel() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
    }

    @Test func aSystemNamesWhatItHolds() throws {
        let source = try #require(architecture.read(payments).source)

        #expect(source.systemAssets == [
            SourceSystemAsset(
                id: "card-numbers",
                name: "Card numbers",
                classification: "restricted",
                description: "The primary account numbers customers type.",
                owner: "Payments team"
            )
        ])
    }

    @Test func aComponentStatesWhatItHoldsAndAFlowWhatItCarries() throws {
        let source = try #require(architecture.read(payments).source)

        #expect(source.components[0].holds == ["card-numbers"])
        #expect(source.flows[0].carries == ["card-numbers"])
    }

    @Test func anAssetNoBlockDeclaresIsRefused() {
        let text = """
        system "Payments" {
          component "api" {
            technology = "aws-ec2"
            holds      = ["card-numbers"]
          }
        }

        """
        let read = architecture.read(text)

        #expect(read.diagnostics.contains { $0.message.contains("which no asset declares") })
        #expect(read.diagnostics.contains { $0.message.contains("card-numbers") })
    }

    @Test func anAssetWithNoNameIsRefused() {
        let text = """
        system "Payments" {
          asset "card-numbers" { }
        }

        """
        let read = architecture.read(text)

        #expect(read.diagnostics.contains { $0.message.contains("has no name") })
    }

    /// A component that states what it holds and no `data` of its own takes
    /// the highest classification it holds.
    @Test func aComponentTakesTheClassificationOfWhatItHolds() {
        drawTheModel()
        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        let api = canvas.components.first { $0.id == "api" }

        #expect(api?.sensitivityId == "restricted")
    }

    /// A component that states both keeps its own word.
    @Test func aComponentThatStatesDataKeepsIt() {
        drawTheModel()
        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())
        let db = canvas.components.first { $0.id == "db" }

        #expect(db?.sensitivityId == "public")
    }

    @Test func aStatedClassificationBelowAnAssetIsAWarning() {
        let response = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        guard case .imported(_, let warnings, _) = response else {
            Issue.record("the file did not import: \(response)")
            return
        }

        #expect(
            warnings.contains {
                $0.message.contains("db") && $0.message.contains("restricted")
            }
        )
    }

    @Test func aFlowCarryingWhatItsSourceDoesNotHoldIsAWarning() {
        let text = """
        system "Payments" {
          asset "card-numbers" {
            name           = "Card numbers"
            classification = "restricted"
          }

          component "api" {
            technology = "aws-ec2"
            data       = "internal"
          }

          component "db" {
            technology = "aws-rds"
            data       = "internal"
          }

          flow api -> db {
            kind    = "network"
            carries = ["card-numbers"]
          }
        }

        """
        let read = architecture.read(text)

        #expect(read.hasErrors == false)
        #expect(
            read.diagnostics.contains {
                $0.severity == .warning && $0.message.contains("does not hold")
            }
        )
    }

    @Test func aRoundTripWritesTheFileItRead() throws {
        let source = try #require(architecture.read(payments).source)

        let written = architecture.write(source)
        let again = try #require(architecture.read(written).source)

        #expect(again.systemAssets == source.systemAssets)
        #expect(again.components[0].holds == ["card-numbers"])
        #expect(again.flows[0].carries == ["card-numbers"])
        #expect(architecture.write(again) == written)
    }

    /// A component that states no classification of its own writes no `data`
    /// line, so a compile of an unchanged model writes the file it read.
    @Test func formattingKeepsWhatTheFileStated() {
        let written = architecture.write(architecture.read(payments).source!)

        #expect(written.contains("holds      = [\"card-numbers\"]"))
        #expect(written.contains("carries = [\"card-numbers\"]"))
        #expect(written.contains("classification = \"restricted\""))
    }

    @Test func theReportWritesADataInventory() {
        drawTheModel()
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("## Data inventory"))
        #expect(markdown.contains("| Asset | Classification | Owner | Held by | Carried by | Worst open threat |"))
        #expect(markdown.contains("Card numbers"))
        #expect(markdown.contains("Payments team"))
        #expect(markdown.contains("The primary account numbers customers type."))
    }

    @Test func eachThreatNamesTheAssetsAtRiskOnItsSource() {
        drawTheModel()
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("- Assets at risk: Card numbers"))
    }

    @Test func aSystemWithNoAssetWritesNoInventory() {
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  component "api" {
                    technology = "aws-ec2"
                  }
                }

                """
            )
        )
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("## Data inventory") == false)
        #expect(markdown.contains("- Assets at risk:") == false)
    }

    /// An asset labels what is at stake and moves no number.
    @Test func aModelThatDeclaresNoAssetScoresWhatItScoredBefore() {
        let plain = """
        system "Payments" {
          component "api" {
            technology = "aws-ec2"
            data       = "restricted"
          }
        }

        """
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: plain))
        let before = app.assessThreatModel().execute(AssessThreatModelRequest()).threats

        let withAsset = """
        system "Payments" {
          asset "card-numbers" {
            name           = "Card numbers"
            classification = "restricted"
          }

          component "api" {
            technology = "aws-ec2"
            holds      = ["card-numbers"]
          }
        }

        """
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: withAsset))
        let after = app.assessThreatModel().execute(AssessThreatModelRequest()).threats

        #expect(after.map(\.riskScore) == before.map(\.riskScore))
    }

    @Test func aPersonWritesAnAssetAndTakesItOff() {
        drawTheModel()

        #expect(
            app.setSystemAsset().execute(
                SetSystemAssetRequest(
                    id: "session-tokens",
                    name: "Session tokens",
                    classification: "confidential"
                )
            ) == .recorded
        )
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).systemAssets.count == 2)

        #expect(
            app.removeSystemAsset().execute(RemoveSystemAssetRequest(id: "session-tokens"))
                == .removed
        )
        #expect(
            app.removeSystemAsset().execute(RemoveSystemAssetRequest(id: "nothing"))
                == .noSuchAsset
        )
    }

    /// Taking an asset off takes it off everything that held or carried it: a
    /// component holding an asset nothing declares would write a file nobody
    /// can read again.
    @Test func takingAnAssetOffTakesItOffWhatHeldIt() {
        drawTheModel()

        _ = app.removeSystemAsset().execute(RemoveSystemAssetRequest(id: "card-numbers"))
        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())

        #expect(canvas.components.allSatisfy { $0.holds.isEmpty })
        #expect(canvas.connections.allSatisfy { $0.carries.isEmpty })
    }

    @Test func anAssetNeedsAnIdentifierAndAName() {
        #expect(
            app.setSystemAsset().execute(
                SetSystemAssetRequest(id: " ", name: "Card numbers", classification: "restricted")
            ) == .noId
        )
        #expect(
            app.setSystemAsset().execute(
                SetSystemAssetRequest(id: "card-numbers", name: " ", classification: "restricted")
            ) == .noName
        )
        #expect(
            app.setSystemAsset().execute(
                SetSystemAssetRequest(id: "card-numbers", name: "Card numbers", classification: "money")
            ) == .unknownClassification
        )
    }

    @Test func aPersonStatesWhatAComponentHoldsAndAFlowCarries() {
        drawTheModel()

        #expect(
            app.setComponentProperties().execute(
                SetComponentPropertiesRequest(
                    componentId: "api",
                    name: nil,
                    sensitivity: "restricted",
                    threatsDisabled: false,
                    runsAs: "user",
                    holds: ["nothing-declares-this"]
                )
            ) == .unknownAsset
        )
        #expect(
            app.setConnectionAssets().execute(
                SetConnectionAssetsRequest(connectionId: "api->db", carries: ["card-numbers"])
            ) == .updated
        )
        #expect(
            app.setConnectionAssets().execute(
                SetConnectionAssetsRequest(connectionId: "nothing", carries: [])
            ) == .unknownConnection
        )
    }

    @Test func aSavedModelKeepsTheAssets() throws {
        drawTheModel()
        let codec = ThreatModelCodec()
        let saved = try codec.encode(model())
        let read = try codec.decode(saved)

        #expect(read.systemAssets.map(\.id) == ["card-numbers"])
        #expect(read.components.first { $0.id == ComponentId("api") }?.holds == ["card-numbers"])
        #expect(read.connections.first?.carries == ["card-numbers"])
    }

    private func model() -> ThreatModel {
        ThreatModel(
            name: "Payments",
            components: [
                Component(
                    id: ComponentId("api"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: DataSensitivity("restricted"),
                    holds: ["card-numbers"],
                    statesOwnSensitivity: false
                )
            ],
            connections: [
                Connection(
                    id: ConnectionId("api->db"),
                    source: ComponentId("api"),
                    target: ComponentId("db"),
                    carries: ["card-numbers"]
                )
            ],
            systemAssets: [
                SystemAsset(
                    id: "card-numbers",
                    name: "Card numbers",
                    classification: DataSensitivity("restricted")
                )
            ]
        )
    }
}
