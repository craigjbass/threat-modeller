import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// A library that changes what the catalogue says about a threat.
@Suite("A library's override")
struct LibraryOverrideTests {
    private let library = """
    library "acme" {
      name = "Acme Platform"

      override "credential-theft" {
        severity    = "low"
        likelihood  = "research"
        description = "Acme's own words about credential theft."

        control "Rotate the keys every day"
      }
    }
    """

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }
    """

    private func withTheLibrary(_ text: String? = nil) -> TestDependencies {
        let app = TestDependencies()
        app.project.put(text ?? library, at: "/work/threatmodel/library/acme.lib")
        app.project.put(payments, at: "/work/threatmodel/payments.arch")
        guard case .loaded(let libraries, _) = app.loadLibraries()
            .execute(LoadLibrariesRequest(root: "/work")) else { return app }
        app.useLibraries(libraries)
        return app
    }

    @Test func readsTheOverrideBlock() throws {
        let source = try #require(HclLibrarySource().read(library).source)

        #expect(source.overrides == [
            SourceLibraryOverride(
                threatId: "credential-theft",
                severityLabel: "low",
                likelihood: "research",
                description: "Acme's own words about credential theft.",
                controlDescriptions: ["Rotate the keys every day"]
            )
        ])
    }

    @Test func theCatalogueAnswersWithTheLibrarysWords() throws {
        let app = withTheLibrary()

        let threat = try #require(
            app.catalogueInUse.threatsFor(technologyId: TechnologyId("aws-ec2"))
                .first { $0.id == ThreatId("credential-theft") }
        )

        #expect(threat.severity.id == "low")
        #expect(threat.likelihood == .research)
        #expect(threat.description == "Acme's own words about credential theft.")
        #expect(threat.controls.map(\.description) == ["Rotate the keys every day"])
    }

    /// An override states what it changes and nothing else.
    @Test func anOverrideThatStatesOneThingChangesOneThing() throws {
        let app = withTheLibrary(
            """
            library "acme" {
              override "credential-theft" {
                severity = "low"
              }
            }
            """
        )
        let plain = CatalogueFixture.catalogue()
            .threatsFor(technologyId: TechnologyId("aws-ec2"))
            .first { $0.id == ThreatId("credential-theft") }

        let threat = try #require(
            app.catalogueInUse.threatsFor(technologyId: TechnologyId("aws-ec2"))
                .first { $0.id == ThreatId("credential-theft") }
        )

        #expect(threat.severity.id == "low")
        #expect(threat.description == plain?.description)
        #expect(threat.controls == plain?.controls)
    }

    @Test func refusesAnOverrideOfAThreatTheCatalogueDoesNotHold() {
        let app = TestDependencies()
        app.project.put(
            """
            library "acme" {
              override "not-a-threat" {
                severity = "low"
              }
            }
            """,
            at: "/work/threatmodel/library/acme.lib"
        )
        app.project.put(payments, at: "/work/threatmodel/payments.arch")

        let response = app.loadLibraries().execute(LoadLibrariesRequest(root: "/work"))

        guard case .refused(_, let diagnostics) = response else {
            Issue.record("expected the library to be refused, got \(response)")
            return
        }
        #expect(diagnostics.contains { $0.message.contains("not-a-threat") })
    }

    /// The merge order: the catalogue, then each library by file name, then
    /// the per-model override.
    @Test func aLaterLibraryWinsOverAnEarlierOne() throws {
        let app = TestDependencies()
        app.project.put(
            """
            library "acme" {
              override "credential-theft" { severity = "low" }
            }
            """,
            at: "/work/threatmodel/library/acme.lib"
        )
        app.project.put(
            """
            library "beta" {
              override "credential-theft" { severity = "medium" }
            }
            """,
            at: "/work/threatmodel/library/beta.lib"
        )
        app.project.put(payments, at: "/work/threatmodel/payments.arch")
        guard case .loaded(let libraries, _) = app.loadLibraries()
            .execute(LoadLibrariesRequest(root: "/work")) else {
            Issue.record("expected the libraries to load")
            return
        }
        app.useLibraries(libraries)

        let threat = try #require(
            app.catalogueInUse.threatsFor(technologyId: TechnologyId("aws-ec2"))
                .first { $0.id == ThreatId("credential-theft") }
        )

        #expect(threat.severity.id == "medium")
    }

    /// The per-model override is applied after the catalogue has answered, so
    /// it still wins.
    @Test func thePerModelOverrideStillWins() throws {
        let app = withTheLibrary()
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let threat = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.threatId == "credential-theft" }
        )
        #expect(threat.severityId == "low")

        _ = app.overrideThreatSeverity().execute(
            OverrideThreatSeverityRequest(overrideKey: threat.overrideKey, severityId: "critical")
        )

        let again = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.threatId == "credential-theft" }
        )
        #expect(again.severityId == "critical")
    }

    @Test func theReportNamesTheLibraryTheValueCameFrom() throws {
        let app = withTheLibrary()
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let markdown = app.exportModelAsMarkdown()
            .execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("Changed by the library: Acme Platform"))
    }

    @Test func aRoundTripThroughTheWriterKeepsTheOverride() throws {
        let read = try #require(HclLibrarySource().read(library).source)

        let again = try #require(HclLibrarySource().read(HclLibrarySource().write(read)).source)

        #expect(again.overrides == read.overrides)
    }
}
