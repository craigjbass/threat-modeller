import Testing
import ThreatModelKit
import ArchitectureDSL
import TestSupport

@Suite("A threat actor in a file")
struct ThreatActorLanguageTests {
    private let libraries = HclLibrarySource()
    private let architecture = HclArchitectureSource()

    private func libraryErrors(_ text: String) -> [String] {
        libraries.read(text).diagnostics.filter { $0.severity == .error }.map(\.message)
    }

    private func architectureErrors(_ text: String) -> [String] {
        architecture.read(text).diagnostics.filter { $0.severity == .error }.map(\.message)
    }

    private let block = """
    library "acme" {
      threat_actor "insider" {
        name        = "Disgruntled operator"
        description = "A person with production access who has resigned."
        aliases     = ["leaver"]
        capability  = "commodity"
        intent      = "sabotage"
        performs    = ["data-exfiltration", "credential-theft"]
        techniques  = ["T1078", "T1530"]
      }
    }
    """

    @Test func readsEveryAttributeOfALibraryBlock() throws {
        let source = try #require(libraries.read(block).source)

        let actor = try #require(source.threatActors.first)
        #expect(actor.id == "insider")
        #expect(actor.name == "Disgruntled operator")
        #expect(actor.description == "A person with production access who has resigned.")
        #expect(actor.aliases == ["leaver"])
        #expect(actor.capability == "commodity")
        #expect(actor.intent == "sabotage")
        #expect(actor.performs == ["data-exfiltration", "credential-theft"])
        #expect(actor.techniques == ["T1078", "T1530"])
        #expect(actor.performsCatalogueTier == nil)
    }

    @Test func writesALibraryBlockBackUnchanged() throws {
        let source = try #require(libraries.read(block).source)

        let written = libraries.write(source)

        #expect(try #require(libraries.read(written).source) == source)
        #expect(written.contains("threat_actor \"insider\""))
    }

    @Test func mintsALibraryActorIdWithTheLibrarysLabel() throws {
        let source = try #require(libraries.read(block).source)

        let built = Library.build(from: source, taxonomy: CatalogueFixture.taxonomy())

        let actor = try #require(built.library?.threatActors.first)
        #expect(actor.id == ThreatActorId("acme-insider"))
        #expect(actor.capability == .commodity)
    }

    @Test func readsAFacesListAndALocalBlock() throws {
        let source = try #require(architecture.read("""
        system "Payments" {
          faces = ["commodity-crimeware", "acme-insider"]

          threat_actor "contractor" {
            name       = "Third-party contractor"
            capability = "targeted"
            intent     = "financial"
            performs   = ["supply-chain-compromise"]
          }
        }
        """).source)

        #expect(source.faces == ["commodity-crimeware", "acme-insider"])
        #expect(source.threatActors.map(\.id) == ["contractor"])
        #expect(source.threatActors.first?.capability == "targeted")
    }

    @Test func writesAFacesListAndALocalBlockBackUnchanged() throws {
        let text = """
        system "Payments" {
          faces = ["commodity-crimeware"]

          threat_actor "contractor" {
            name       = "Third-party contractor"
            capability = "targeted"
          }
        }
        """
        let source = try #require(architecture.read(text).source)

        let written = architecture.write(source)

        #expect(try #require(architecture.read(written).source) == source)
    }

    @Test func keepsTheLastFacesListWhenAFileStatesTwo() throws {
        let source = try #require(architecture.read("""
        system "Payments" {
          faces = ["one"]
          faces = ["two"]
        }
        """).source)

        #expect(source.faces == ["two"])
    }

    @Test func refusesAnActorWithNoName() {
        #expect(
            libraryErrors("""
            library "acme" {
              threat_actor "insider" {
                capability = "commodity"
              }
            }
            """) == ["the threat actor \"insider\" has no name"]
        )
    }

    @Test func refusesACapabilityOutsideTheThreeTiers() {
        #expect(
            libraryErrors("""
            library "acme" {
              threat_actor "insider" {
                name       = "Disgruntled operator"
                capability = "nation-state"
              }
            }
            """) == [
                "capability is \"nation-state\"; this application holds \"commodity\", "
                    + "\"targeted\", \"research\""
            ]
        )
    }

    @Test func refusesACatalogueTierOutsideTheThreeTiers() {
        #expect(
            libraryErrors("""
            library "acme" {
              threat_actor "insider" {
                name                    = "Disgruntled operator"
                performs_catalogue_tier = "everything"
              }
            }
            """) == [
                "performs_catalogue_tier is \"everything\"; this application holds "
                    + "\"commodity\", \"targeted\", \"research\""
            ]
        )
    }

    @Test func refusesADuplicateActorIdInOneLibrary() {
        #expect(
            libraryErrors("""
            library "acme" {
              threat_actor "insider" {
                name = "One"
              }
              threat_actor "insider" {
                name = "Two"
              }
            }
            """) == ["the threat actor \"insider\" is declared twice"]
        )
    }

    @Test func refusesADuplicateActorIdInOneSystem() {
        #expect(
            architectureErrors("""
            system "Payments" {
              threat_actor "contractor" {
                name = "One"
              }
              threat_actor "contractor" {
                name = "Two"
              }
            }
            """) == ["the threat actor \"contractor\" is declared twice"]
        )
    }
}
