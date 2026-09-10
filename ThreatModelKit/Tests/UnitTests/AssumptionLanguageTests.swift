import ArchitectureDSL
import Testing
import ThreatModelKit

@Suite("Assumptions and the risk tolerance in an architecture file")
struct AssumptionLanguageTests {
    private let gateway = HclArchitectureSource()

    private let text = """
    system "clearancekit" {
      risk_tolerance = "medium"

      assumption "mdm-push" {
        text  = "the hardening baseline is written, and MDM has not pushed it yet"
        owner = "platform team"
      }

      component "laptop" {
        technology = "workstation"
      }

      component "hardening" {
        technology = "es-client"
      }

      mitigates hardening -> laptop {
        threats         = ["persistence"]
        reduces_risk_by = 60
        status          = "assumed"
      }
    }
    """

    private func errors(_ text: String) -> [Diagnostic] {
        gateway.read(text).diagnostics.filter { $0.severity == .error }
    }

    @Test func readsTheToleranceTheAssumptionAndTheStatus() throws {
        let source = try #require(gateway.read(text).source)

        #expect(source.riskTolerance == "medium")
        #expect(source.assumptions.first?.label == "mdm-push")
        #expect(source.assumptions.first?.owner == "platform team")
        #expect(source.mitigates.first?.status == "assumed")
    }

    @Test func anEdgeThatStatesNoStatusIsAdopted() throws {
        let plain = text.replacingOccurrences(of: "    status          = \"assumed\"\n", with: "")
        let source = try #require(gateway.read(plain).source)
        #expect(source.mitigates.first?.status == nil)
    }

    @Test func refusesAStatusTheApplicationDoesNotHold() throws {
        let wrong = text.replacingOccurrences(of: "\"assumed\"", with: "\"hoped\"")
        #expect(errors(wrong).count == 1)
    }

    @Test func refusesAToleranceTheRiskLadderDoesNotHold() throws {
        let wrong = text.replacingOccurrences(of: "\"medium\"", with: "\"relaxed\"")
        #expect(errors(wrong).count == 1)
    }

    @Test func refusesAnAssumptionWithNoText() throws {
        let wrong = text.replacingOccurrences(
            of: "    text  = \"the hardening baseline is written, and MDM has not pushed it yet\"\n",
            with: ""
        )
        #expect(errors(wrong).count == 1)
    }

    @Test func refusesTwoAssumptionsWithOneLabel() throws {
        let twice = text.replacingOccurrences(
            of: "  component \"laptop\" {",
            with: """
              assumption "mdm-push" {
                text = "said twice"
              }

              component "laptop" {
            """
        )
        #expect(errors(twice).count == 1)
    }

    @Test func writesEverythingBackAndReadsWhatItWrote() throws {
        let source = try #require(gateway.read(text).source)
        #expect(try #require(gateway.read(gateway.write(source)).source) == source)
    }
}
