import ArchitectureDSL
import FileGateways
import Testing
import ThreatModelKit
import TestSupport

@Suite("What the model covers and what it leaves out")
struct ScopeTests {
    private let app = TestDependencies()
    private let architecture = HclArchitectureSource()

    private let payments = """
    system "Payments" {
      use_case "take-a-payment" {
        text = "A customer pays for a basket."
      }

      exclusion "the card network" {
        text      = "This model does not cover the card network."
        rationale = "Another team owns it and models it."
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    @Test func aFileStatesWhatAPersonDoesWithTheSystem() throws {
        let source = try #require(architecture.read(payments).source)

        #expect(source.useCases == [
            SourceUseCase(label: "take-a-payment", text: "A customer pays for a basket.")
        ])
    }

    @Test func aFileStatesWhatTheModelDoesNotCover() throws {
        let source = try #require(architecture.read(payments).source)

        #expect(source.exclusions == [
            SourceExclusion(
                label: "the card network",
                text: "This model does not cover the card network.",
                rationale: "Another team owns it and models it."
            )
        ])
    }

    @Test func anExclusionWithNoReasonIsRefused() {
        let text = """
        system "Payments" {
          exclusion "the card network" {
            text = "This model does not cover the card network."
          }
        }

        """
        let read = architecture.read(text)

        #expect(read.diagnostics.contains { $0.message.contains("has no rationale") })
        #expect(read.hasErrors)
    }

    @Test func aUseCaseWithNoTextIsRefused() {
        let text = """
        system "Payments" {
          use_case "take-a-payment" { }
        }

        """
        let read = architecture.read(text)

        #expect(read.diagnostics.contains { $0.message.contains("has no text") })
    }

    /// A thing both drawn and excluded is a contradiction.
    @Test func anExclusionNamingADrawnComponentIsAWarning() {
        let text = """
        system "Payments" {
          exclusion "api" {
            text      = "This model does not cover the api."
            rationale = "Another team owns it."
          }

          component "api" {
            technology = "aws-ec2"
          }
        }

        """
        let read = architecture.read(text)
        let warnings = read.diagnostics.filter { $0.severity == .warning }

        #expect(warnings.contains { $0.message.contains("both drawn and excluded") })
        #expect(read.hasErrors == false)
    }

    @Test func aRoundTripWritesTheFileItRead() throws {
        let source = try #require(architecture.read(payments).source)

        let written = architecture.write(source)
        let again = try #require(architecture.read(written).source)

        #expect(again.useCases == source.useCases)
        #expect(again.exclusions == source.exclusions)
        #expect(architecture.write(again) == written)
    }

    @Test func drawingTheFileKeepsBoth() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let canvas = app.viewThreatModel().execute(ViewThreatModelRequest())

        #expect(canvas.useCases.map(\.label) == ["take-a-payment"])
        #expect(canvas.exclusions.map(\.label) == ["the card network"])
    }

    @Test func aPersonWritesAUseCaseAndTakesItOff() {
        #expect(
            app.setSystemUseCase().execute(
                SetSystemUseCaseRequest(label: "take-a-payment", text: "A customer pays.")
            ) == .recorded
        )
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).useCases.count == 1)

        #expect(
            app.removeSystemUseCase().execute(
                RemoveSystemUseCaseRequest(label: "take-a-payment")
            ) == .removed
        )
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).useCases.isEmpty)
    }

    @Test func aUseCaseWrittenTwiceChangesTheOneThatIsThere() {
        _ = app.setSystemUseCase().execute(
            SetSystemUseCaseRequest(label: "take-a-payment", text: "A customer pays.")
        )
        _ = app.setSystemUseCase().execute(
            SetSystemUseCaseRequest(label: "take-a-payment", text: "A customer pays by card.")
        )
        let written = app.viewThreatModel().execute(ViewThreatModelRequest()).useCases

        #expect(written.count == 1)
        #expect(written[0].text == "A customer pays by card.")
    }

    @Test func aUseCaseThatSaysNothingIsRefused() {
        #expect(
            app.setSystemUseCase().execute(
                SetSystemUseCaseRequest(label: "take-a-payment", text: "   ")
            ) == .noText
        )
        #expect(
            app.setSystemUseCase().execute(
                SetSystemUseCaseRequest(label: " ", text: "A customer pays.")
            ) == .noLabel
        )
    }

    @Test func anExclusionWithNoReasonIsRefusedOnScreenToo() {
        #expect(
            app.setExclusion().execute(
                SetExclusionRequest(label: "the card network", text: "Not covered.", rationale: " ")
            ) == .noRationale
        )
    }

    @Test func aPersonWritesAnExclusionAndTakesItOff() {
        #expect(
            app.setExclusion().execute(
                SetExclusionRequest(
                    label: "the card network",
                    text: "Not covered.",
                    rationale: "Another team owns it."
                )
            ) == .recorded
        )
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).exclusions.count == 1)

        #expect(
            app.removeExclusion().execute(
                RemoveExclusionRequest(label: "the card network")
            ) == .removed
        )
        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()).exclusions.isEmpty)
        #expect(
            app.removeExclusion().execute(
                RemoveExclusionRequest(label: "nothing")
            ) == .noSuchExclusion
        )
    }

    @Test func theReportWritesAScopeSection() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("## Scope"))
        #expect(markdown.contains("### Use cases"))
        #expect(markdown.contains("- take-a-payment: A customer pays for a basket."))
        #expect(markdown.contains("### Exclusions"))
        #expect(markdown.contains("  - Rationale: Another team owns it and models it."))
    }

    /// The Scope section reads after the one page a reader reads first.
    @Test func scopeComesAfterTheExecutiveSummary() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        let summary = try #require(markdown.range(of: "## Executive summary"))
        let scope = try #require(markdown.range(of: "## Scope"))
        #expect(summary.lowerBound < scope.lowerBound)
    }

    @Test func theSummaryStatesHowManyThingsTheModelLeavesOut() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("This model states 1 exclusion, listed under Scope."))
    }

    @Test func aSystemThatStatesNeitherWritesNoSection() {
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

        #expect(markdown.contains("## Scope") == false)
        #expect(markdown.contains("listed under Scope") == false)
    }

    @Test func aSavedModelKeepsBoth() throws {
        let model = ThreatModel(
            name: "Payments",
            useCases: [SystemUseCase(label: "take-a-payment", text: "A customer pays.")],
            exclusions: [
                SystemExclusion(
                    label: "the card network",
                    text: "Not covered.",
                    rationale: "Another team owns it."
                )
            ]
        )
        let codec = ThreatModelCodec()
        let read = try codec.decode(try codec.encode(model))

        #expect(read.useCases == model.useCases)
        #expect(read.exclusions == model.exclusions)
    }

    @Test func theScopeSectionHeadsAnAdversaryApartFromTheLegitimateUsers() throws {
        let lines = MarkdownScope.lines(
            useCases: [],
            exclusions: [],
            users: [
                ReportUser(name: "Alice", role: "Operator", accessLabel: "Administrator"),
                ReportUser(
                    name: "Phisher",
                    role: "Customer",
                    accessLabel: "User",
                    isAdversary: true
                )
            ]
        )

        let users = try #require(lines.firstIndex(of: "### Users"))
        let adversaries = try #require(lines.firstIndex(of: "### Adversaries"))
        let alice = try #require(lines.firstIndex { $0.hasPrefix("- Alice") })
        let phisher = try #require(lines.firstIndex { $0.hasPrefix("- Phisher") })
        #expect(users < alice)
        #expect(alice < adversaries)
        #expect(adversaries < phisher)
    }

    @Test func aModelWithNoAdversaryHeadsOnlyTheUsers() {
        let lines = MarkdownScope.lines(
            useCases: [],
            exclusions: [],
            users: [ReportUser(name: "Alice", accessLabel: "User")]
        )

        #expect(lines.contains("### Users"))
        #expect(lines.contains("### Adversaries") == false)
    }

    @Test func aModelWithNoLegitimateUserHeadsOnlyTheAdversaries() {
        let lines = MarkdownScope.lines(
            useCases: [],
            exclusions: [],
            users: [ReportUser(name: "Phisher", accessLabel: "User", isAdversary: true)]
        )

        #expect(lines.contains("### Adversaries"))
        #expect(lines.contains("### Users") == false)
    }
}
