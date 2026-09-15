import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// A team's own words for how sensitive its data is.
@Suite("A classification scheme a library states")
struct ClassificationSchemeTests {
    private let library = """
    library "hmg" {
      name = "Government Scheme"

      classification "official" {
        name   = "Official"
        colour = "#4c7a34"
      }

      classification "official-sensitive" {
        name = "Official Sensitive"
      }

      classification "secret" {
        name = "Secret"
      }

      classification "top-secret" {
        name = "Top Secret"
      }
    }
    """

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "secret"
      }
    }
    """

    private func withTheScheme() -> TestDependencies {
        let app = TestDependencies()
        app.project.put(library, at: "/work/threatmodel/library/hmg.lib")
        app.project.put(payments, at: "/work/threatmodel/payments.arch")
        guard case .loaded(let libraries, _) = app.loadLibraries()
            .execute(LoadLibrariesRequest(root: "/work")) else { return app }
        app.useLibraries(libraries)
        return app
    }

    @Test func readsTheLevelsInTheOrderTheFileStatesThem() throws {
        let source = try #require(HclLibrarySource().read(library).source)

        #expect(source.classifications.map(\.id)
            == ["official", "official-sensitive", "secret", "top-secret"])
        #expect(source.classifications[0].colour == "#4c7a34")
    }

    @Test func theProjectTakesTheLibrarysLevels() {
        let listed = withTheScheme().listClassifications()
            .execute(ListClassificationsRequest())

        #expect(listed.classifications.map(\.id)
            == ["official", "official-sensitive", "secret", "top-secret"])
        #expect(listed.libraryLabel == "Government Scheme")
    }

    /// The score reads the position in the order, not the id. `secret` is
    /// third, so it ranks 3, which is what `confidential` ranks in the
    /// standard scheme: critical (4) times 3 is 12.
    @Test func theScoreReadsThePositionInTheOrder() throws {
        let app = withTheScheme()
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let threat = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.threatId == "credential-theft" }
        )

        #expect(threat.riskScore == 12)
    }

    /// A five level scheme scores too: the fifth level ranks 5.
    @Test func aFiveLevelSchemeScores() {
        let scheme = ClassificationScheme(
            levels: (1 ... 5).map { Classification(id: "level-\($0)", label: "Level \($0)") }
        )

        #expect(scheme.rank(of: "level-1") == 1)
        #expect(scheme.rank(of: "level-5") == 5)
        #expect(
            RiskScore(
                severity: ThreatSeverity(id: "critical", label: "Critical", rank: 4),
                sensitivity: DataSensitivity("level-5"),
                classifications: scheme
            ).value == 20
        )
    }

    @Test func aLevelNoSchemeHoldsRanksOne() {
        #expect(ClassificationScheme.standard.rank(of: "not-a-level") == 1)
        #expect(ClassificationScheme.standard.label(of: "not-a-level") == "not-a-level")
    }

    @Test func theReportPrintsTheLibrarysLabels() {
        let app = withTheScheme()
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let markdown = app.exportModelAsMarkdown()
            .execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("Secret"))
    }

    @Test func twoLibrariesThatStateASchemeNameBoth() throws {
        let app = TestDependencies()
        app.project.put(library, at: "/work/threatmodel/library/hmg.lib")
        app.project.put(
            """
            library "other" {
              classification "one" { name = "One" }
            }
            """,
            at: "/work/threatmodel/library/other.lib"
        )
        app.project.put(payments, at: "/work/threatmodel/payments.arch")

        guard case .loaded(_, let warnings) = app.loadLibraries()
            .execute(LoadLibrariesRequest(root: "/work")) else {
            Issue.record("expected the libraries to load")
            return
        }

        let said = try #require(
            warnings.first { $0.message.contains("classification scheme") }
        )
        #expect(said.message.contains("\"hmg\""))
        #expect(said.message.contains("\"other\""))
    }

    @Test func aProjectThatReadsNoSuchLibraryKeepsTheFourLevels() throws {
        let app = TestDependencies()
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

        let listed = app.listClassifications().execute(ListClassificationsRequest())
        #expect(listed.classifications.map(\.id)
            == ["public", "internal", "confidential", "restricted"])
        #expect(listed.libraryLabel == nil)

        let threat = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.threatId == "credential-theft" }
        )
        #expect(threat.riskScore == 12)
    }

    @Test func aRoundTripThroughTheWriterKeepsTheScheme() throws {
        let read = try #require(HclLibrarySource().read(library).source)

        let again = try #require(HclLibrarySource().read(HclLibrarySource().write(read)).source)

        #expect(again.classifications == read.classifications)
    }

    /// A word the project's scheme does not hold is said, and the diagram is
    /// still drawn.
    @Test func saysWhatTheSchemeDoesNotHold() throws {
        let app = TestDependencies()

        let response = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  component "api" {
                    technology = "aws-ec2"
                    data       = "secret"
                  }
                }
                """
            )
        )

        guard case .imported(_, let warnings, _) = response else {
            Issue.record("expected the file to be drawn, got \(response)")
            return
        }
        #expect(warnings.contains { $0.message.contains("data is \"secret\"") })
        #expect(app.modelStore.current().components.count == 1)
    }
}
