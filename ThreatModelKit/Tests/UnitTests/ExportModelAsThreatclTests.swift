import CommandLineApplication
import Foundation
import Testing
@testable import ThreatModelKit
import TestSupport

@Suite("Writing the model as threatcl")
struct ExportModelAsThreatclTests {
    private let app = TestDependencies()
    private let project = InMemoryProject(root: "/work")

    /// One sample system holding every part the export writes: an asset, a
    /// third party, an assumption, a use case, an exclusion, a zone, an
    /// actor, a store and two flows.
    private let payments = """
    system "Payments" {
      owner        = "Payments team"
      description  = "Takes card payments."
      authors      = ["Craig"]
      links        = ["https://example.com/design"]
      repositories = ["https://github.com/example/payments"]

      asset "card-numbers" {
        name           = "Card numbers"
        classification = "restricted"
        description    = "The primary account numbers."
      }

      third_party "stripe" {
        name            = "Stripe"
        kind            = "saas"
        paying_customer = true
        uptime          = "hard"
        uptime_notes    = "No payment is taken while Stripe is down."
      }

      assumption "network-segmented" {
        text = "The VPC has no route to the internet."
      }

      use_case "take-a-payment" {
        text = "A customer pays for a basket."
      }

      exclusion "the card network" {
        text      = "This model does not cover the card network."
        rationale = "Another team owns it."
      }

      zone "app" {
        kind = "private"

        component "api" {
          technology  = "aws-ec2"
          holds       = ["card-numbers"]
          provided_by = "stripe"
        }

        component "db" {
          technology = "aws-rds"
          data       = "restricted"
        }
      }

      component "attacker" {
        technology = "actor-attacker"
      }

      flow attacker -> api
      flow api -> db
    }

    """

    private func exported() -> String {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        return app.exportModelAsThreatcl().execute(ExportModelAsThreatclRequest()).hcl
    }

    // MARK: what the file states, block by block

    @Test func statesTheSpecVersionTheReleaseHolds() {
        #expect(exported().hasPrefix("spec_version = \"\(ExportModelAsThreatcl.specVersion)\"\n"))
        #expect(ExportModelAsThreatcl.specVersion == "0.8.1")
    }

    @Test func theThreatmodelStatesTheModelsOwnAuthorAndFacts() {
        let hcl = exported()

        #expect(hcl.contains("threatmodel \"Payments\" {"))
        #expect(hcl.contains("  author = \"Craig\""))
        #expect(hcl.contains("  description = \"Takes card payments.\""))
        #expect(hcl.contains("  link = \"https://example.com/design\""))
        #expect(hcl.contains("  repository = [\"https://github.com/example/payments\"]"))
    }

    @Test func eachAssetIsAnInformationAsset() {
        let hcl = exported()

        #expect(hcl.contains("  information_asset \"Card numbers\" {"))
        #expect(hcl.contains("    description = \"The primary account numbers.\""))
        #expect(hcl.contains("    information_classification = \"Restricted\""))
    }

    @Test func eachUseCaseIsAUsecaseAndEachExclusionAnExclusion() {
        let hcl = exported()

        #expect(hcl.contains("  usecase {"))
        #expect(hcl.contains("    description = \"take-a-payment: A customer pays for a basket.\""))
        #expect(hcl.contains("  exclusion {"))
        #expect(hcl.contains("the card network: This model does not cover the card network."))
    }

    /// threatcl states one kind of exclusion, and an assumption is a thing
    /// the assessment left unchecked.
    @Test func eachAssumptionIsAnExclusion() {
        #expect(
            exported().contains(
                "    description = \"Assumed: network-segmented: "
                    + "The VPC has no route to the internet.\""
            )
        )
    }

    @Test func eachThirdPartyIsAThirdPartyDependency() {
        let hcl = exported()

        #expect(hcl.contains("  third_party_dependency \"Stripe\" {"))
        #expect(hcl.contains("    saas = \"true\""))
        #expect(hcl.contains("    paying_customer = \"true\""))
        #expect(hcl.contains("    uptime_dependency = \"hard\""))
        #expect(hcl.contains("    uptime_notes = \"No payment is taken while Stripe is down.\""))
    }

    @Test func eachThreatIsLabelledAndStatesItsRisk() {
        let hcl = exported()

        #expect(hcl.contains("  threat \"Credential Theft on EC2\" {"))
        #expect(hcl.contains("    impacts = ["))
        #expect(hcl.contains("\"Confidentiality\""))
        #expect(hcl.contains("    stride = ["))
        #expect(hcl.contains("\"Elevation Of Privilege\""))
        #expect(hcl.contains("    information_asset_refs = [\"Card numbers\"]"))
        #expect(hcl.contains("    risk {"))
        #expect(hcl.contains("      likelihood = \"high\""))
        #expect(hcl.contains("      impact = \"very_high\""))
        #expect(hcl.contains("      severity = \"critical\""))
        #expect(hcl.contains("      rationale = \""))
    }

    @Test func eachControlIsItsOwnBlock() {
        let hcl = exported()

        #expect(hcl.contains("    control \"Enforce IMDSv2"))
        #expect(hcl.contains("      implemented = false"))
        #expect(hcl.contains("      risk_reduction = 0"))
        #expect(hcl.contains("control = \"") == false)
    }

    @Test func anImplementedControlTakesTheWholeRisk() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let first = app.assessThreatModel().execute(AssessThreatModelRequest()).threats[0]
        let text = """
        controls for "Payments" {
          threat "\(first.threatId)" on component "api" {
            severity = "\(first.severityLabel)"
            score    = \(first.riskScore)

            control "\(first.controls[0].description)" {
              status = "implemented"
              note   = "Okta"
            }
          }
        }

        """
        _ = app.applyControlAnswers().execute(ApplyControlAnswersRequest(text: text))

        let hcl = app.exportModelAsThreatcl().execute(ExportModelAsThreatclRequest()).hcl
        #expect(hcl.contains("      implemented = true"))
        #expect(hcl.contains("      risk_reduction = 100"))
    }

    /// Issue #259: threatcl holds no clearance, so a clearance travels as
    /// the control it is, with the reduction it states.
    @Test func aClearanceTravelsAsAControl() {
        let source = LibrarySource(
            label: "endpoint",
            technologies: [
                SourceTechnology(
                    id: "laptop",
                    name: "Laptop",
                    category: "compute",
                    threatIds: ["key-copying"]
                )
            ],
            threats: [
                SourceLibraryThreat(
                    id: "key-copying",
                    name: "An operator copies a key",
                    severityLabel: "critical",
                    likelihood: "insider"
                )
            ]
        )
        let (library, _) = Library.build(from: source, taxonomy: CatalogueFixture.taxonomy())
        app.useLibraries([library!])
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  clearance "sc" {
                    name                    = "Security Check"
                    reduces_insider_risk_by = 60
                    rationale               = "The vetting reads the whole employment record."
                  }

                  component "api" {
                    technology = "endpoint-laptop"
                    data       = "restricted"
                  }

                  user "alice" {
                    reaches   = ["api"]
                    clearance = "sc"
                  }
                }

                """
            )
        )

        let hcl = app.exportModelAsThreatcl().execute(ExportModelAsThreatclRequest()).hcl

        #expect(
            hcl.contains(
                "control \"Security clearance \\\"Security Check\\\", held by alice\" {"
            )
        )
        #expect(
            hcl.contains(
                "      description = \"The vetting reads the whole employment record.\""
            )
        )
        #expect(hcl.contains("      risk_reduction = 60"))
    }

    @Test func theDiagramHoldsTheZonesTheElementsAndTheFlows() {
        let hcl = exported()

        #expect(hcl.contains("  data_flow_diagram_v2 \"Payments DFD\" {"))
        #expect(hcl.contains("    trust_zone \"Private Zone\" {"))
        #expect(hcl.contains("      process \"EC2\" {"))
        #expect(hcl.contains("      data_store \"RDS\" {"))
        // The fixture catalogue holds no actor technology, so the attacker
        // draws as a process. `element(of:)` below states the mapping itself.
        #expect(hcl.contains("    process \"actor-attacker\" {"))
        #expect(hcl.contains("    flow \"Network\" {"))
        #expect(hcl.contains("      from = \"actor-attacker\""))
        #expect(hcl.contains("      to = \"EC2\""))
        #expect(hcl.contains("      protocol = \"Network\""))
        #expect(hcl.contains("information_asset \"Payments\"") == false)
    }

    @Test func eachShapeIsItsOwnKindOfElement() {
        func component(shaped shapeId: String) -> ReportComponent {
            ReportComponent(
                id: "one",
                name: "One",
                technologyId: "aws-ec2",
                categoryId: "compute",
                sensitivityLabel: "Confidential",
                zoneName: nil,
                shapeId: shapeId
            )
        }

        #expect(ExportModelAsThreatcl.element(of: component(shaped: "actor")) == "external_element")
        #expect(ExportModelAsThreatcl.element(of: component(shaped: "store")) == "data_store")
        #expect(ExportModelAsThreatcl.element(of: component(shaped: "process")) == "process")
    }

    @Test func aThreatOnTwoElementsTakesTwoLabels() {
        let hcl = exported()
        let labels = hcl
            .split(separator: "\n")
            .filter { $0.hasPrefix("  threat \"") }
            .map(String.init)

        #expect(labels.count > 1)
        #expect(Set(labels).count == labels.count)
    }

    @Test func aStrideWordIsWrittenInThreatclsOwnWords() {
        #expect(ExportModelAsThreatcl.stride(of: "Information Disclosure") == "Info Disclosure")
        #expect(ExportModelAsThreatcl.stride(of: "Denial of Service") == "Denial Of Service")
        #expect(ExportModelAsThreatcl.stride(of: "Spoofing") == "Spoofing")
    }

    @Test func aTierTravelsByItsOwnFactorNotByASwitchOnItsWord() {
        #expect(ExportModelAsThreatcl.likelihood(of: "Commodity") == "high")
        #expect(ExportModelAsThreatcl.likelihood(of: "Targeted") == "medium")
        #expect(ExportModelAsThreatcl.likelihood(of: "Insider") == "medium")
        #expect(ExportModelAsThreatcl.likelihood(of: "Research") == "low")
    }

    @Test func aFactorAtOrAboveNinetyPercentTravelsAsHigh() {
        #expect(ExportModelAsThreatcl.likelihood(factor: 0.9) == "high")
        #expect(ExportModelAsThreatcl.likelihood(factor: 1.0) == "high")
    }

    @Test func aFactorAtOrBelowThirtyPercentTravelsAsLow() {
        #expect(ExportModelAsThreatcl.likelihood(factor: 0.3) == "low")
        #expect(ExportModelAsThreatcl.likelihood(factor: 0.0) == "low")
    }

    @Test func aFactorBetweenThirtyAndNinetyPercentTravelsAsMedium() {
        #expect(ExportModelAsThreatcl.likelihood(factor: 0.6) == "medium")
    }

    @Test func aNumericPriorOfNinetyPercentTravelsAsHighAndFivePercentAsLow() {
        #expect(ExportModelAsThreatcl.likelihood(of: "90%") == "high")
        #expect(ExportModelAsThreatcl.likelihood(of: "5%") == "low")
        #expect(ExportModelAsThreatcl.likelihood(of: "60%") == "medium")
    }

    /// threatcl holds three classifications, and a project's own scheme may
    /// hold more.
    @Test func aClassificationOutsideTheThreeTravelsAsConfidential() {
        #expect(ExportModelAsThreatcl.classification(of: "Public") == "Public")
        #expect(ExportModelAsThreatcl.classification(of: "Restricted") == "Restricted")
        #expect(ExportModelAsThreatcl.classification(of: "Internal") == "Confidential")
        #expect(ExportModelAsThreatcl.classification(of: "Board only") == "Confidential")
    }

    // MARK: the golden file

    /// The whole file for one sample system. `threatcl validate` accepts this
    /// file at the pinned release, and CI runs the binary when it is present.
    @Test func theExportMatchesTheGoldenFile() throws {
        let golden = try String(
            contentsOf: Self.goldensDirectory.appendingPathComponent("payments.threatcl.hcl"),
            encoding: .utf8
        )

        #expect(exported() == golden)
    }

    @Test func writesTheGoldenFileWhenAskedTo() throws {
        guard ProcessInfo.processInfo.environment["THREATMODELLER_WRITE_GOLDENS"] == "1" else {
            return
        }
        try exported().write(
            to: Self.goldensDirectory.appendingPathComponent("payments.threatcl.hcl"),
            atomically: true,
            encoding: .utf8
        )
    }

    private static var goldensDirectory: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Goldens")
    }

    // MARK: the verb

    @Test func theExportVerbWritesTheFile() throws {
        project.put(payments, at: "/work/threatmodel/payments.arch")
        var lines: [String] = []
        let code = CommandLineApplication(
            projects: project,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(
            arguments: ["threatmodeller", "export", "/work", "--format", "threatcl"],
            output: { lines.append($0) }
        )

        #expect(code == 0)
        let written = try #require(project.text(at: "/work/threatmodel/payments.hcl"))
        #expect(written.hasPrefix("spec_version"))
    }
}
