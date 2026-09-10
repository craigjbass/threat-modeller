import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("Where a piece of evidence comes from")
struct EvidenceSourcesTests {
    private let gateway = HclControlsSource()

    private let text = """
    controls for "Payments" {
      threat "credential-theft" on component "api" {
        compensating "Break-glass account watched by the SIEM" {
          reduces_risk_by = 40
          rationale       = "The one account left alerts on use."
          sources         = ["https://example.test/adr/17"]
        }

        recommendation "Allow-list hardened-runtime binaries only" {
          note    = "Homebrew builds are ad-hoc signed"
          sources = ["https://attack.mitre.org/techniques/T1218/"]
        }
      }
    }
    """

    @Test func readsTheSourcesOfBothBlocks() throws {
        let answer = try #require(gateway.read(text).source?.answers.first)
        #expect(answer.compensating.first?.sources == ["https://example.test/adr/17"])
        #expect(answer.recommendations.first?.sources == ["https://attack.mitre.org/techniques/T1218/"])
    }

    @Test func writesThemBackAndReadsWhatItWrote() throws {
        let source = try #require(gateway.read(text).source)
        #expect(try #require(gateway.read(gateway.write(source)).source) == source)
    }

    @Test func aBlockWithNoSourcesReadsAsAnEmptyList() throws {
        let plain = """
        controls for "Payments" {
          threat "credential-theft" on component "api" {
            compensating "Watched" {
              reduces_risk_by = 40
              rationale       = "It alerts on use."
            }
          }
        }
        """
        let answer = try #require(gateway.read(plain).source?.answers.first)
        #expect(answer.compensating.first?.sources == [])
        #expect(gateway.write(try #require(gateway.read(plain).source)).contains("sources") == false)
    }
}
