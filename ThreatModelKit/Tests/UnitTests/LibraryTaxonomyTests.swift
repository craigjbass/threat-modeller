import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// A library that adds a word to the taxonomy.
@Suite("A library's own taxonomy")
struct LibraryTaxonomyTests {
    private let source = """
    library "acme" {
      name = "Acme Platform"

      category "operational-technology" {
        name = "Operational Technology"
      }

      severity "catastrophic" {
        name = "Catastrophic"
      }

      stride "safety" {
        name = "Safety"
      }

      technology "plc" {
        name     = "Programmable Logic Controller"
        category = "operational-technology"
        threats  = ["ladder-logic-tamper"]
      }

      threat "ladder-logic-tamper" {
        name     = "Ladder logic tampering"
        severity = "catastrophic"
        stride   = ["safety"]

        control "Sign the ladder logic"
      }
    }
    """

    private func read(_ text: String) -> LibraryRead {
        HclLibrarySource().read(text)
    }

    private func built(_ text: String) -> (library: Library?, faults: [LibraryBuildFault]) {
        guard let source = read(text).source else { return (nil, []) }
        return Library.build(from: source, taxonomy: CatalogueFixture.catalogue().taxonomy())
    }

    @Test func readsACategoryASeverityAndAStrideCategory() throws {
        let source = try #require(read(source).source)

        #expect(source.categories == [
            SourceTaxonomyEntry(id: "operational-technology", label: "Operational Technology")
        ])
        #expect(source.severities == [SourceTaxonomyEntry(id: "catastrophic", label: "Catastrophic")])
        #expect(source.strides == [SourceTaxonomyEntry(id: "safety", label: "Safety")])
    }

    @Test func aWordTheLibraryDeclaresIsKnownToItsOwnTechnologyAndThreat() throws {
        let built = built(source)

        #expect(built.faults.isEmpty)
        let library = try #require(built.library)
        #expect(library.technologies[0].category == CategoryId("operational-technology"))
        #expect(library.threats[0].severity.id == "catastrophic")
        #expect(library.threats[0].stride == [StrideId("safety")])
    }

    @Test func aWordNothingDeclaresIsStillAFault() {
        let built = built(
            """
            library "acme" {
              technology "plc" {
                name     = "PLC"
                category = "not-a-category"
              }
            }
            """
        )

        #expect(built.library == nil)
        #expect(built.faults.contains { $0.message.contains("not-a-category") })
    }

    @Test func theMergedCatalogueHoldsTheLibrarysWords() throws {
        let library = try #require(built(source).library)
        let store = LibraryStore()
        store.set([library])
        let merged = MergedCatalogue(base: CatalogueFixture.catalogue(), store: store)

        let taxonomy = merged.taxonomy()

        #expect(taxonomy.category(id: CategoryId("operational-technology"))?.label
            == "Operational Technology")
        #expect(taxonomy.severity(id: "catastrophic")?.label == "Catastrophic")
        #expect(taxonomy.strideCategory(id: StrideId("safety"))?.label == "Safety")
    }

    /// A library severity is worse than every vendored one, so it ranks above
    /// them all.
    @Test func aLibrarySeverityRanksAboveEveryVendoredOne() throws {
        let library = try #require(built(source).library)
        let store = LibraryStore()
        store.set([library])
        let merged = MergedCatalogue(base: CatalogueFixture.catalogue(), store: store)
        let taxonomy = merged.taxonomy()

        let added = try #require(taxonomy.severity(id: "catastrophic"))
        #expect(taxonomy.severities.allSatisfy { $0.id == added.id || $0.rank < added.rank })
    }

    @Test func aLibraryThatDeclaresNoneKeepsTheVendoredTaxonomy() {
        let base = CatalogueFixture.catalogue()
        let store = LibraryStore()
        store.set([])
        let merged = MergedCatalogue(base: base, store: store)

        #expect(merged.taxonomy() == base.taxonomy())
    }

    @Test func aRoundTripThroughTheWriterKeepsTheWords() throws {
        let read = try #require(read(source).source)

        let written = HclLibrarySource().write(read)
        let again = try #require(HclLibrarySource().read(written).source)

        #expect(again.categories == read.categories)
        #expect(again.severities == read.severities)
        #expect(again.strides == read.strides)
    }
}

/// Two libraries that declare one word.
@Suite("Two libraries, one word")
struct ClashingLibraryTaxonomyTests {
    private func library(_ label: String) -> String {
        """
        library "\(label)" {
          category "operational-technology" {
            name = "Operational Technology"
          }
        }
        """
    }

    @Test func namesBothLibraries() throws {
        let app = TestDependencies()
        app.project.put(library("acme"), at: "/work/threatmodel/library/acme.lib")
        app.project.put(library("beta"), at: "/work/threatmodel/library/beta.lib")

        let response = app.loadLibraries().execute(LoadLibrariesRequest(root: "/work"))

        guard case .loaded(let libraries, let warnings) = response else {
            Issue.record("expected the libraries to load, got \(response)")
            return
        }
        #expect(libraries.count == 2)
        let said = try #require(warnings.first { $0.message.contains("operational-technology") })
        #expect(said.message.contains("\"acme\""))
        #expect(said.message.contains("\"beta\""))
    }

    @Test func theFirstOneReadStands() throws {
        let app = TestDependencies()
        app.project.put(
            """
            library "acme" {
              category "shared" { name = "Acme's word" }
            }
            """,
            at: "/work/threatmodel/library/acme.lib"
        )
        app.project.put(
            """
            library "beta" {
              category "shared" { name = "Beta's word" }
            }
            """,
            at: "/work/threatmodel/library/beta.lib"
        )
        guard case .loaded(let libraries, _) = app.loadLibraries()
            .execute(LoadLibrariesRequest(root: "/work")) else {
            Issue.record("expected the libraries to load")
            return
        }
        let store = LibraryStore()
        store.set(libraries)

        let taxonomy = MergedCatalogue(base: CatalogueFixture.catalogue(), store: store).taxonomy()

        #expect(taxonomy.category(id: CategoryId("shared"))?.label == "Acme's word")
    }
}

/// A pathway mitigation a library states.
@Suite("A library's own pathway mitigation")
struct LibraryPathwayMitigationTests {
    private let source = """
    library "acme" {
      name = "Acme Platform"

      technology "firewall" {
        name     = "Acme Firewall"
        category = "compute"
      }

      threat "lateral-movement" {
        name     = "Lateral movement"
        severity = "high"
        pathway  = true

        control "Segment the network"
      }

      mitigation "network-firewall" {
        name            = "Acme Network Firewall"
        mitigates       = ["lateral-movement"]
        provided_by     = ["firewall"]
        reduces_risk_by = 50
        mode            = "remove"
      }
    }
    """

    private func loaded() -> [Library] {
        let app = TestDependencies()
        app.project.put(source, at: "/work/threatmodel/library/acme.lib")
        let response = app.loadLibraries().execute(LoadLibrariesRequest(root: "/work"))
        guard case .loaded(let libraries, _) = response else {
            Issue.record("the library did not load: \(response)")
            return []
        }
        return libraries
    }

    @Test func theLibraryStatesTheMitigationAndTheThreatItAnswers() throws {
        let library = try #require(loaded().first)

        let mitigation = try #require(library.pathwayMitigations.first)
        #expect(mitigation.id == PathwayMitigationId("acme-network-firewall"))
        #expect(mitigation.reducesRiskBy == 50)
        #expect(mitigation.defaultMode == .remove)
        #expect(mitigation.technologyIds == [TechnologyId("acme-firewall")])
        #expect(library.threats[0].isPathwayThreat)
    }

    @Test func theMitigationNamesTheLibraryItCameFrom() throws {
        let library = try #require(loaded().first)

        #expect(library.pathwayMitigations.first?.libraryLabel == "Acme Platform")
    }

    @Test func thePanelListsTheVendoredOnesAndTheLibrarysTogether() throws {
        let app = TestDependencies()
        app.project.put(source, at: "/work/threatmodel/library/acme.lib")
        guard case .loaded(let libraries, _) = app.loadLibraries()
            .execute(LoadLibrariesRequest(root: "/work")) else {
            Issue.record("expected the library to load")
            return
        }
        app.useLibraries(libraries)

        let listed = app.listPathwayMitigations()
            .execute(ListPathwayMitigationsRequest()).mitigations

        #expect(listed.contains { $0.id == "acme-network-firewall" })
        #expect(listed.contains { $0.libraryLabel == nil })
        #expect(listed.first { $0.id == "acme-network-firewall" }?.libraryLabel == "Acme Platform")
    }

    @Test func aModelThatReadsNoLibraryShowsTheVendoredOnesOnly() {
        let app = TestDependencies()

        let listed = app.listPathwayMitigations()
            .execute(ListPathwayMitigationsRequest()).mitigations

        #expect(listed.allSatisfy { $0.libraryLabel == nil })
    }
}
