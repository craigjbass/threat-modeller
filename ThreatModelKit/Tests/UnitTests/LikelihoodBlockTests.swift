import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("The likelihood block in a controls file")
struct LikelihoodBlockTests {
    private let gateway = HclControlsSource()

    private func controls(_ block: String) -> String {
        """
        controls for "Payments" {
          threat "sip-bypass" on component "laptop" {
        \(block)
          }
        }
        """
    }

    private func errors(_ text: String) -> [Diagnostic] {
        gateway.read(text).diagnostics.filter { $0.severity == .error }
    }

    @Test func readsATierWithARationaleAndItsSources() throws {
        let text = controls("""
            likelihood "no in-the-wild use" {
              tier      = "research"
              rationale = "every bypass was researcher-found"
              sources   = ["https://example.test/a", "CVE-2021-30892"]
            }
        """)
        let source = try #require(gateway.read(text).source)
        let finding = try #require(source.answers.first?.likelihood)

        #expect(finding.label == "no in-the-wild use")
        #expect(finding.likelihood == .research)
        #expect(finding.rationale == "every bypass was researcher-found")
        #expect(finding.sources == ["https://example.test/a", "CVE-2021-30892"])
    }

    @Test func readsANumericPrior() throws {
        let text = controls("""
            likelihood "one campaign in five years" {
              prior     = 20
              rationale = "one campaign, 2021, no repeat"
            }
        """)
        let finding = try #require(gateway.read(text).source?.answers.first?.likelihood)
        #expect(finding.likelihood.factor == 0.2)
    }

    @Test func refusesABlockWithNoRationale() throws {
        let text = controls("""
            likelihood "no in-the-wild use" {
              tier = "research"
            }
        """)
        let found = errors(text)
        #expect(found.count == 1)
        #expect(found.first?.message.contains("rationale") == true)
    }

    @Test func refusesABlockThatStatesBothATierAndAPrior() throws {
        let text = controls("""
            likelihood "two numbers" {
              tier      = "research"
              prior     = 20
              rationale = "it says both"
            }
        """)
        #expect(errors(text).count == 1)
    }

    @Test func refusesTwoBlocksOnOneThreat() throws {
        let text = controls("""
            likelihood "first" {
              tier      = "research"
              rationale = "one"
            }

            likelihood "second" {
              tier      = "targeted"
              rationale = "two"
            }
        """)
        #expect(errors(text).count == 1)
    }

    @Test func writesTheBlockBackInTheCanonicalShape() throws {
        let text = controls("""
            likelihood "no in-the-wild use" {
              tier      = "research"
              rationale = "every bypass was researcher-found"
              sources   = ["https://example.test/a"]
            }
        """)
        let source = try #require(gateway.read(text).source)
        let written = gateway.write(source)
        let again = try #require(gateway.read(written).source)

        #expect(again == source)
        #expect(written.contains("likelihood \"no in-the-wild use\" {"))
        #expect(written.contains("sources   = [\"https://example.test/a\"]"))
    }
}
