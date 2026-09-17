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

        #expect(response == .imported(name: "Payments", warnings: [], catalogueTag: "v1.0.1"))
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

    /// A flow that states what it carries writes back the same bytes. The
    /// builder must pass `carries` through with every other flow field.
    @Test func writesBackAFileWhoseFlowStatesWhatItCarries() {
        let text = """
        system "Payments" {
          asset "card-numbers" {
            name           = "Card numbers"
            classification = "restricted"
          }

          component "api" {
            technology = "aws-ec2"
            holds      = ["card-numbers"]
          }

          component "db" {
            technology = "aws-rds"
            data       = "public"
            holds      = ["card-numbers"]
          }

          flow api -> db {
            kind    = "network"
            carries = ["card-numbers"]
          }
        }

        """

        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: text))

        let exported = app.exportArchitecture().execute(ExportArchitectureRequest())

        #expect(exported.text == text)
    }

    /// Editing an unrelated field on the window and saving again must not
    /// drop what an existing flow carries.
    @Test func keepsWhatAFlowCarriesWhenAnUnrelatedFieldChanges() {
        let text = """
        system "Payments" {
          asset "card-numbers" {
            name           = "Card numbers"
            classification = "restricted"
          }

          component "api" {
            technology = "aws-ec2"
            holds      = ["card-numbers"]
          }

          component "db" {
            technology = "aws-rds"
            data       = "public"
            holds      = ["card-numbers"]
          }

          flow api -> db {
            kind    = "network"
            carries = ["card-numbers"]
          }
        }

        """
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: text))

        // An edit to the name, which the flow's carries has nothing to do
        // with.
        _ = app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: "db",
                name: "Database",
                sensitivity: "public",
                threatsDisabled: false,
                runsAs: "user"
            )
        )

        let exported = app.exportArchitecture().execute(ExportArchitectureRequest())

        #expect(exported.text.contains("name       = \"Database\""))
        #expect(exported.text.contains("carries = [\"card-numbers\"]"))
        #expect(
            app.viewThreatModel().execute(ViewThreatModelRequest())
                .connections.first?.carries == ["card-numbers"]
        )
    }

    /// A component that forces a shape writes back the same bytes. The
    /// builder must pass `shape` through with every other component field.
    @Test func writesBackAFileWhoseComponentStatesAShape() {
        let text = """
        system "Payments" {
          component "cache" {
            technology = "aws-ec2"
            shape      = "store"
          }
        }

        """

        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: text))

        let exported = app.exportArchitecture().execute(ExportArchitectureRequest())

        #expect(exported.text == text)
    }

    /// A zone that states a description and a source writes back the same
    /// bytes. The builder must pass both through with every other zone field.
    @Test func writesBackAFileWhoseZoneStatesADescriptionAndASource() {
        let text = """
        system "Payments" {
          zone "app" {
            kind            = "private"
            network         = "generic"
            reduces_risk_by = 20
            description     = "internal traffic only"
            source          = "terraform"
          }
        }

        """

        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: text))

        let exported = app.exportArchitecture().execute(ExportArchitectureRequest())

        #expect(exported.text == text)
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

    @Test func exportsAStatedLowToleranceAndAStatedAdoptedStatus() {
        let statingTheDefaults = """
        system "S" {
          risk_tolerance = "low"

          component "laptop" { technology = "aws-ec2" data = "confidential" }
          component "baseline" { technology = "actor-user" data = "internal" }

          mitigates baseline -> laptop {
            threats         = ["credential-theft"]
            reduces_risk_by = 60
            status          = "adopted"
          }
        }
        """
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: statingTheDefaults))

        let text = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(text.contains("risk_tolerance = \"low\""))
        #expect(text.contains("status          = \"adopted\""))
    }

    @Test func exportsAnAssumedEdgesRecommendationAndAnAdoptedEdgeWithNone() {
        let withARecommendation = """
        system "S" {
          assumption "guard-not-deployed" {
            text = "the guard is bought and not deployed"
          }

          component "laptop" { technology = "aws-ec2" data = "confidential" }
          component "baseline" { technology = "actor-user" data = "internal" }
          component "store" { technology = "aws-ec2" data = "confidential" }

          mitigates baseline -> laptop {
            threats         = ["credential-theft"]
            reduces_risk_by = 60
            status          = "assumed"

            recommendation "adopt-the-guard" {
              text       = "Adopt the guard"
              note       = "It is bought and not deployed."
              blocked_by = "guard-not-deployed"
              sources    = ["https://example.com/ticket/1"]
            }
          }

          mitigates laptop -> store {
            threats         = ["credential-theft"]
            reduces_risk_by = 40
            status          = "adopted"
          }
        }
        """
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: withARecommendation))

        let text = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(text.contains("recommendation \"adopt-the-guard\" {"))
        #expect(text.contains("text       = \"Adopt the guard\""))
        #expect(text.contains("note       = \"It is bought and not deployed.\""))
        #expect(text.contains("blocked_by = \"guard-not-deployed\""))
        #expect(text.contains("sources    = [\"https://example.com/ticket/1\"]"))
        #expect(text.contains("mitigates laptop -> store {"))
        // The adopted edge carries no recommendation block of its own.
        let laptopToStore = text.range(of: "mitigates laptop -> store {")!
        let afterLaptopToStore = text[laptopToStore.upperBound...]
        let nextBlockClose = afterLaptopToStore.range(of: "}")!
        #expect(afterLaptopToStore[..<nextBlockClose.lowerBound].contains("recommendation") == false)
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
