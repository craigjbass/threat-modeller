import ArchitectureDSL
import CatalogueGateways
import FileGateways
import Foundation
import Testing
import ThreatModelKit
import TestSupport

@Suite("What a threat harms")
struct ThreatImpactTests {
    private let app = TestDependencies()
    private let controls = HclControlsSource()

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func drawTheModel() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
    }

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    @Test func spoofingHarmsConfidentiality() {
        #expect(ThreatImpact.derived(from: [StrideId("spoofing")]) == [.confidentiality])
    }

    @Test func tamperingHarmsIntegrity() {
        #expect(ThreatImpact.derived(from: [StrideId("tampering")]) == [.integrity])
    }

    @Test func denialOfServiceHarmsAvailability() {
        #expect(ThreatImpact.derived(from: [StrideId("denial-of-service")]) == [.availability])
    }

    @Test func elevationOfPrivilegeHarmsAllThree() {
        #expect(ThreatImpact.derived(from: [StrideId("elevation-of-privilege")]) == ThreatImpact.allCases)
    }

    @Test func twoCategoriesHarmBothInOneOrder() {
        let derived = ThreatImpact.derived(from: [StrideId("tampering"), StrideId("spoofing")])
        #expect(derived == [.confidentiality, .integrity])
    }

    @Test func aThreatStatingNoStrideHarmsAllThree() {
        #expect(ThreatImpact.derived(from: []) == ThreatImpact.allCases)
    }

    @Test func aWordOutsideTheThreeIsNoImpact() {
        #expect(ThreatImpact(rawValue: "money") == nil)
    }

    /// Nothing the vendored catalogue holds may end with no impact: a threat
    /// with none states nothing about what it harms.
    @Test func everyVendoredThreatHoldsAnImpact() throws {
        let catalogue = try BundledTechnologyCatalogue()
        var read = 0
        var every = catalogue.connectionThreats() + catalogue.zoneThreats()
        for technology in catalogue.all() {
            every += catalogue.threatsFor(technologyId: technology.id)
        }
        for threat in every {
            #expect(threat.impacts.isEmpty == false, "\(threat.id.value) states no impact")
            read += 1
        }
        #expect(read > 0)
    }

    @Test func aLibraryStatesWhatItsThreatHarms() throws {
        let text = """
        library "acme" {
          threat "leak" {
            name     = "It leaks"
            severity = "high"
            stride   = ["denial-of-service"]
            impacts  = ["confidentiality"]
          }
        }

        """
        let source = try #require(HclLibrarySource().read(text).source)
        #expect(source.threats[0].impacts == ["confidentiality"])
    }

    @Test func aLibraryRefusesAWordOutsideTheThree() {
        let text = """
        library "acme" {
          threat "leak" {
            name     = "It leaks"
            severity = "high"
            impacts  = ["money"]
          }
        }

        """
        let read = HclLibrarySource().read(text)
        #expect(read.diagnostics.contains { $0.message.contains("money") })
        #expect(read.diagnostics.contains { $0.message.contains("confidentiality") })
    }

    @Test func aControlsFileStatesWhatAThreatHarmsInThisSystem() throws {
        drawTheModel()
        let first = threats()[0]
        let text = """
        controls for "Payments" {
          threat "\(first.threatId)" on component "api" {
            severity = "\(first.severityLabel)"
            score    = \(first.riskScore)
            impacts  = ["availability"]
          }
        }

        """
        let source = try #require(controls.read(text).source)
        #expect(source.answers[0].impacts == ["availability"])

        let response = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))
        guard case .applied = response else {
            Issue.record("the file did not apply: \(response)")
            return
        }
        let applied = try #require(threats().first { $0.threatId == first.threatId })
        #expect(applied.impacts == ["availability"])
    }

    /// A stated impact labels a threat and moves no number.
    @Test func statingAnImpactChangesNoScore() throws {
        drawTheModel()
        let before = threats()
        let first = before[0]
        let text = """
        controls for "Payments" {
          threat "\(first.threatId)" on component "api" {
            severity = "\(first.severityLabel)"
            score    = \(first.riskScore)
            impacts  = ["availability"]
          }
        }

        """
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))
        let after = threats()
        #expect(after.map(\.riskScore) == before.map(\.riskScore))
        #expect(after.map(\.riskLevel) == before.map(\.riskLevel))
    }

    /// A compile writes the file again, and what the team stated survives it.
    @Test func aCompileKeepsWhatTheTeamStated() throws {
        drawTheModel()
        let first = threats()[0]
        let stated = """
        controls for "Payments" {
          threat "\(first.threatId)" on component "api" {
            severity = "\(first.severityLabel)"
            score    = \(first.riskScore)
            impacts  = ["availability"]
          }
        }

        """
        guard case .compiled(let text, _, _, _, _, _, _) = app.compileControls().execute(
            CompileControlsRequest(architectureText: payments, controlsText: stated)
        ) else {
            Issue.record("the controls did not compile")
            return
        }
        let source = try #require(controls.read(text).source)
        let answer = try #require(source.answers.first { $0.threatId == first.threatId })
        #expect(answer.impacts == ["availability"])
    }

    /// A saved file carries what the team stated, so a reopen reads it back.
    @Test func aSavedModelKeepsWhatTheTeamStated() throws {
        let key = ThreatKey(threatId: "t-credential-theft", sourceId: "component:api")
        let model = ThreatModel(
            name: "Payments",
            impactOverrides: [key: [.availability]]
        )
        let codec = ThreatModelCodec()
        let read = try codec.decode(try codec.encode(model))
        #expect(read.impactOverrides[key] == [.availability])
    }

    @Test func theReportNamesWhatEachThreatHarms() {
        drawTheModel()
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
        #expect(markdown.contains("- Impact: "))
    }

    @Test func theSummaryCountsOpenThreatsByImpact() {
        drawTheModel()
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown
        #expect(markdown.contains("Those threats harm "))
    }
}
