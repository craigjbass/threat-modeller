import ArchitectureDSL
import FileGateways
import Testing
import ThreatModelKit
import TestSupport

/// What a system states about itself, and what the report says about it.
@Suite("Document control")
struct DocumentControlTests {
    private let payments = """
    system "Payments" {
      description  = "The service that takes a card payment."
      owner        = "The Payments Team"
      authors      = ["Ada Lovelace", "Alan Turing"]
      version      = "2.1"
      created      = "2026-01-04"
      reviewed     = "2026-09-01"
      links        = ["https://example.internal/design/payments"]
      repositories = ["https://example.internal/git/payments"]

      attribute "data-controller" {
        value = "Acme Payments Limited"
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }
    """

    private func read(_ text: String) -> ArchitectureRead {
        HclArchitectureSource().read(text)
    }

    // MARK: the language

    @Test func readsEveryDocumentAttribute() throws {
        let source = try #require(read(payments).source)

        #expect(source.description == "The service that takes a card payment.")
        #expect(source.owner == "The Payments Team")
        #expect(source.authors == ["Ada Lovelace", "Alan Turing"])
        #expect(source.version == "2.1")
        #expect(source.created == "2026-01-04")
        #expect(source.reviewed == "2026-09-01")
        #expect(source.links == ["https://example.internal/design/payments"])
        #expect(source.repositories == ["https://example.internal/git/payments"])
        #expect(source.attributes == [
            SourceSystemAttribute(name: "data-controller", value: "Acme Payments Limited")
        ])
    }

    @Test func refusesADayTheCalendarDoesNotHold() {
        let read = read("system \"P\" { created = \"2026-02-30\" }")

        #expect(read.hasErrors)
        #expect(read.diagnostics.contains { $0.message.contains("2026-02-30") })
    }

    @Test func refusesADateOfTheWrongShape() {
        let read = read("system \"P\" { reviewed = \"4 January 2026\" }")

        #expect(read.hasErrors)
        #expect(read.diagnostics.contains { $0.message.contains("YYYY-MM-DD") })
    }

    @Test func refusesALinkThatIsNotAnAddress() {
        let read = read("system \"P\" { links = [\"the design doc\"] }")

        #expect(read.hasErrors)
        #expect(read.diagnostics.contains { $0.message.contains("is not an address") })
    }

    @Test func refusesAnAttributeDeclaredTwice() {
        let read = read(
            """
            system "P" {
              attribute "owner-team" { value = "one" }
              attribute "owner-team" { value = "two" }
            }
            """
        )

        #expect(read.hasErrors)
        #expect(read.diagnostics.contains { $0.message.contains("declared twice") })
    }

    // MARK: the canonical form

    @Test func aRoundTripThroughTheWriterGivesTheSameFile() throws {
        let source = try #require(read(payments).source)

        let written = HclArchitectureSource().write(source)
        let again = try #require(read(written).source)

        #expect(HclArchitectureSource().write(again) == written)
        #expect(again.authors == source.authors)
        #expect(again.attributes == source.attributes)
        #expect(again.created == source.created)
    }

    @Test func writesTheAttributesInTheCanonicalOrder() throws {
        let source = try #require(read(payments).source)

        let written = HclArchitectureSource().write(source)
        let order = ["description", "owner", "authors", "version", "created", "reviewed", "links", "repositories"]
        let positions = order.compactMap { written.range(of: "\($0) ")?.lowerBound }

        #expect(positions.count == order.count)
        #expect(positions == positions.sorted())
    }

    // MARK: the model and the document

    @Test func theModelCarriesWhatTheFileStates() throws {
        let app = TestDependencies()

        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let facts = app.modelStore.current().documentFacts
        #expect(facts.authors == ["Ada Lovelace", "Alan Turing"])
        #expect(facts.version == "2.1")
        #expect(app.modelStore.current().owner == "The Payments Team")
    }

    @Test func aDocumentRoundTripKeepsTheFacts() throws {
        let app = TestDependencies()
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let data = try ThreatModelCodec().encode(app.modelStore.current())
        let read = try ThreatModelCodec().decode(data)

        #expect(read.documentFacts == app.modelStore.current().documentFacts)
        #expect(read.owner == "The Payments Team")
    }

    @Test func aDocumentThatStatesNoneReadsBackWithNone() throws {
        let model = ThreatModel(name: "Payments")

        let read = try ThreatModelCodec().decode(try ThreatModelCodec().encode(model))

        #expect(read.documentFacts.isEmpty)
        #expect(read.owner.isEmpty)
    }

    // MARK: the report

    @Test func theReportOpensWithTheTable() throws {
        let app = TestDependencies()
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let markdown = app.exportModelAsMarkdown()
            .execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("## Document control"))
        #expect(markdown.contains("| Owner | The Payments Team |"))
        #expect(markdown.contains("| Authors | Ada Lovelace, Alan Turing |"))
        #expect(markdown.contains("| Version | 2.1 |"))
        #expect(markdown.contains("| data-controller | Acme Payments Limited |"))
        #expect(markdown.contains("The service that takes a card payment."))
    }

    @Test func aSystemThatStatesNoneWritesNoTable() {
        let app = TestDependencies()
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: "system \"Payments\" { component \"api\" { technology = \"aws-ec2\" } }"
            )
        )

        let markdown = app.exportModelAsMarkdown()
            .execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("## Document control") == false)
    }

    /// A model nobody has read again inside the interval is marked.
    @Test func theSummaryMarksAModelNobodyHasReadAgain() {
        let control = DocumentControl(systemName: "Payments", reviewed: "2020-01-01")
        let today = GovernanceDate(year: 2026, month: 9, day: 15)

        #expect(control.isOverdue(on: today!))
        #expect(
            DocumentControl(systemName: "Payments", reviewed: "2026-09-01")
                .isOverdue(on: today!) == false
        )
        #expect(DocumentControl(systemName: "Payments").isOverdue(on: today!) == false)
    }

    @Test func theIntervalIsOneConstant() {
        #expect(DocumentControl.reviewIntervalDays == 180)
    }

    /// Document control labels a model and moves no number.
    @Test func theScoresAreTheScoresWithoutIt() {
        let bare = TestDependencies()
        _ = bare.importArchitecture().execute(
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
        let stated = TestDependencies()
        _ = stated.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let one = bare.assessThreatModel().execute(AssessThreatModelRequest()).threats
            .map { "\($0.threatId)=\($0.riskScore)" }.sorted()
        let other = stated.assessThreatModel().execute(AssessThreatModelRequest()).threats
            .map { "\($0.threatId)=\($0.riskScore)" }.sorted()

        #expect(one == other)
    }
}
