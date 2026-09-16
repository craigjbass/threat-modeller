import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// The `status` a component states: `live` for a component deployed to
/// Production, `proposed` for one a team plans and has not deployed. A
/// component that states nothing is live, so every file written before this
/// attribute reads and writes unchanged.
@Suite("The status a component states")
struct ComponentStatusTests {
    private let app = TestDependencies()
    private let architecture = HclArchitectureSource()

    private let planned = """
    system "Payments" {
      zone "app" {
        kind    = "private"
        network = "vpc"

        component "api" {
          technology = "aws-ec2"
        }

        component "ledger" {
          technology = "aws-rds"
          status     = "proposed"
        }
      }
    }

    """

    private let deployed = """
    system "Payments" {
      zone "app" {
        kind    = "private"
        network = "vpc"

        component "api" {
          technology = "aws-ec2"
        }
      }
    }

    """

    // MARK: the language

    @Test func theParserReadsTheStatusOnAComponent() throws {
        let source = try #require(architecture.read(planned).source)

        #expect(source.zones[0].components[1].status == "proposed")
    }

    @Test func aComponentThatStatesNoStatusIsLive() throws {
        let source = try #require(architecture.read(deployed).source)

        #expect(source.zones[0].components[0].status == "live")
    }

    @Test func aStatusOutsideTheVocabularyIsAnError() {
        let read = architecture.read(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                status     = "retired"
              }
            }

            """
        )

        #expect(read.source == nil || read.diagnostics.isEmpty == false)
        #expect(read.diagnostics.contains { $0.message.contains("status") })
    }

    @Test func aProposedFileRoundTripsByteForByte() throws {
        let source = try #require(architecture.read(planned).source)

        #expect(architecture.write(source) == planned)
    }

    @Test func aFileWithNoStatusRoundTripsByteForByte() throws {
        let source = try #require(architecture.read(deployed).source)

        #expect(architecture.write(source) == deployed)
    }

    // MARK: the model and the window

    @Test func theModelKeepsTheStatusTheFileStates() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: planned))

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())

        #expect(view.components.first { $0.id == "ledger" }?.statusId == "proposed")
        #expect(view.components.first { $0.id == "api" }?.statusId == "live")
    }

    @Test func aWrittenFileHoldsTheStatusTheModelKeeps() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: planned))

        let written = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(written.contains("status     = \"proposed\""))
    }

    @Test func settingThePropertiesOfAComponentWritesItsStatus() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: planned))

        let answer = app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: "api",
                name: nil,
                sensitivity: "internal",
                threatsDisabled: false,
                runsAs: "user",
                status: "proposed"
            )
        )

        #expect(answer == .updated)
        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.first { $0.id == "api" }?.statusId == "proposed")
    }

    @Test func settingThePropertiesWithNoStatusLeavesTheStatusAlone() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: planned))

        _ = app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: "ledger",
                name: nil,
                sensitivity: "internal",
                threatsDisabled: false,
                runsAs: "user"
            )
        )

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.first { $0.id == "ledger" }?.statusId == "proposed")
    }

    // MARK: the report and the exports

    @Test func theReportStatesTheStatusOfEachComponent() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: planned))

        let report = app.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report

        #expect(report.components.first { $0.id == "ledger" }?.statusLabel == "Proposed")
        #expect(report.components.first { $0.id == "api" }?.statusLabel == "Live")
    }

    @Test func theMarkdownReportStatesTheStatusColumn() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: planned))

        let markdown = app.exportModelAsMarkdown().execute(
            ExportModelAsMarkdownRequest()
        ).markdown

        #expect(markdown.contains("| Name | Technology | Status |"))
        #expect(markdown.contains("| Proposed |"))
    }

    @Test func theJsonExportStatesTheStatusOfEachComponent() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: planned))

        let json = app.exportModelAsJson().execute(ExportModelAsJsonRequest()).json

        #expect(json.contains("\"status\" : \"Proposed\""))
        #expect(json.contains("\"status\" : \"Live\""))
    }

    @Test func theOpenThreatModelExportStatesTheStatusOfEachComponent() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: planned))

        let otm = app.exportModelAsOtm().execute(ExportModelAsOtmRequest()).json

        #expect(otm.contains("\"Proposed\""))
        #expect(otm.contains("\"Live\""))
    }
}
