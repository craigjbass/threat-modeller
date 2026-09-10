import Testing
import ThreatModelKit
import TestSupport

/// Given an architecture written as text and committed
/// When I open it
/// Then I see the diagram it describes and the threats it raises, and writing
/// it back gives the file I started with
struct ModellingFromSourceTests {
    private let app = TestDependencies()

    private let payments = """
    system "Payments" {
      catalogue = "v1.0.1"

      technology "our-ledger" {
        name     = "Our Ledger"
        category = "database"
        threats  = ["credential-theft"]
      }

      zone "app" {
        kind            = "private"
        network         = "vpc"
        reduces_risk_by = 30

        component "api" {
          technology = "aws-ec2"
          name       = "Application Server"
          data       = "confidential"
        }

        component "ledger" {
          technology = "our-ledger"
          data       = "restricted"
        }
      }

      component "user" {
        technology = "actor-user"
        data       = "public"
      }

      flow user -> api
      flow api -> ledger
    }

    """

    @Test func drawsAndScoresWhatTheFileDescribes() {
        let response = app.importArchitecture().execute(
            ImportArchitectureRequest(text: payments)
        )

        #expect(response == .imported(name: "Payments", warnings: []))
        let view = app.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.count == 3)
        #expect(view.connections.count == 2)
        #expect(view.zones.count == 1)
        #expect(app.summariseRisk().execute(SummariseRiskRequest()).totalThreats > 0)
    }

    @Test func writesBackTheFileItRead() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))

        let exported = app.exportArchitecture().execute(ExportArchitectureRequest())

        #expect(exported.fileName == "Payments.arch")
        #expect(exported.text == payments)
    }

    @Test func carriesAChangeMadeOnTheCanvasBackIntoTheFile() throws {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 4000, y: 4000, sensitivity: "restricted")
        ) else {
            Issue.record("the component was not added")
            return
        }
        _ = app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: componentId,
                name: "Reporting Store",
                sensitivity: "restricted",
                threatsDisabled: false,
                runsAs: "user"
            )
        )

        let text = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(text.contains("name       = \"Reporting Store\""))
        // It sits outside every zone, so it is written at the top level.
        #expect(text.contains("  component \"\(componentId)\" {"))
    }

    @Test func readsBackWhatItWroteAsTheSameModel() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let first = app.viewThreatModel().execute(ViewThreatModelRequest())

        let text = app.exportArchitecture().execute(ExportArchitectureRequest()).text
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: text))

        #expect(app.viewThreatModel().execute(ViewThreatModelRequest()) == first)
    }

    @Test func exportsAnAssumedEdgeTwoAssumptionsAndTheTolerance() {
        let withAnAssumption = """
        system "S" {
          risk_tolerance = "high"

          assumption "mdm-push" {
            text  = "the hardening baseline is written, and MDM has not pushed it yet"
            owner = "platform team"
          }

          assumption "network-review" {
            text  = "network segmentation was reviewed last quarter"
            owner = "network team"
          }

          component "laptop" { technology = "aws-ec2" data = "confidential" }
          component "baseline" { technology = "actor-user" data = "internal" }

          mitigates baseline -> laptop {
            threats         = ["credential-theft"]
            reduces_risk_by = 60
            status          = "assumed"
          }
        }
        """
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: withAnAssumption))

        let text = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(text.contains("risk_tolerance = \"high\""))
        #expect(text.contains("assumption \"mdm-push\" {"))
        #expect(text.contains("\"platform team\""))
        #expect(text.contains("assumption \"network-review\" {"))
        #expect(text.contains("\"network team\""))
        #expect(text.contains("mitigates baseline -> laptop {"))
        #expect(text.contains("\"assumed\""))
    }

    @Test func exportsNoStatusNoAssumptionAndNoToleranceAtTheirDefaults() {
        let withNoAssumption = """
        system "S" {
          component "laptop" { technology = "aws-ec2" data = "confidential" }
          component "baseline" { technology = "actor-user" data = "internal" }

          mitigates baseline -> laptop {
            threats         = ["credential-theft"]
            reduces_risk_by = 60
          }
        }
        """
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: withNoAssumption))

        let text = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(text.contains("mitigates baseline -> laptop {"))
        #expect(text.contains("status") == false)
        #expect(text.contains("assumption") == false)
        #expect(text.contains("risk_tolerance") == false)
    }
}
