import ArchitectureDSL
import FileGateways
import Testing
import ThreatModelKit
import TestSupport

@Suite("The parties outside this team the system depends on")
struct ThirdPartyTests {
    private let app = TestDependencies()
    private let architecture = HclArchitectureSource()

    private let payments = """
    system "Payments" {
      third_party "stripe" {
        name            = "Stripe"
        description     = "The company that takes the card payment."
        kind            = "saas"
        paying_customer = true
        uptime          = "hard"
        uptime_notes    = "No payment is taken while Stripe is down."
        owner           = "Payments team"
        link            = "https://stripe.com"
      }

      asset "card-numbers" {
        name           = "Card numbers"
        classification = "restricted"
      }

      assumption "stripe-stays-up" {
        text = "Stripe answers inside its stated service level."
      }

      component "checkout" {
        technology  = "aws-ec2"
        holds       = ["card-numbers"]
        provided_by = "stripe"
      }
    }

    """

    private func drawTheModel() {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: payments))
    }

    @Test func aSystemNamesWhoItDependsOn() throws {
        let source = try #require(architecture.read(payments).source)

        #expect(source.thirdParties.count == 1)
        #expect(source.thirdParties[0].name == "Stripe")
        #expect(source.thirdParties[0].kind == "saas")
        #expect(source.thirdParties[0].payingCustomer)
        #expect(source.thirdParties[0].uptime == "hard")
        #expect(source.thirdParties[0].link == "https://stripe.com")
    }

    @Test func aComponentNamesWhoProvidesIt() throws {
        let source = try #require(architecture.read(payments).source)

        #expect(source.components[0].providedBy == "stripe")
    }

    @Test func aProviderNoBlockDeclaresIsRefused() {
        let text = """
        system "Payments" {
          component "checkout" {
            technology  = "aws-ec2"
            provided_by = "stripe"
          }
        }

        """
        let read = architecture.read(text)

        #expect(read.diagnostics.contains { $0.message.contains("which no third_party declares") })
        #expect(read.diagnostics.contains { $0.message.contains("stripe") })
    }

    @Test func aThirdPartyStatesItsUptimeDependency() {
        let text = """
        system "Payments" {
          third_party "stripe" {
            name = "Stripe"
          }
        }

        """
        let read = architecture.read(text)

        #expect(read.diagnostics.contains { $0.message.contains("states no uptime") })
    }

    @Test func aWordOutsideTheFourIsRefused() {
        let text = """
        system "Payments" {
          third_party "stripe" {
            name   = "Stripe"
            kind   = "vendor"
            uptime = "sometimes"
          }
        }

        """
        let read = architecture.read(text)

        #expect(read.diagnostics.contains { $0.message.contains("kind") })
        #expect(read.diagnostics.contains { $0.message.contains("uptime") })
    }

    /// A dependency nobody has thought about is the one that fails.
    @Test func aHardDependencyNoAssumptionNamesIsAWarning() {
        let text = """
        system "Payments" {
          third_party "stripe" {
            name   = "Stripe"
            uptime = "hard"
          }
        }

        """
        let read = architecture.read(text)

        #expect(read.hasErrors == false)
        #expect(
            read.diagnostics.contains {
                $0.severity == .warning && $0.message.contains("no assumption names it")
            }
        )
    }

    @Test func anAssumptionNamingThePartyAnswersTheWarning() {
        let read = architecture.read(payments)

        #expect(read.diagnostics.contains { $0.message.contains("no assumption names it") } == false)
    }

    @Test func aRoundTripWritesTheFileItRead() throws {
        let source = try #require(architecture.read(payments).source)

        let written = architecture.write(source)
        let again = try #require(architecture.read(written).source)

        #expect(again.thirdParties == source.thirdParties)
        #expect(again.components[0].providedBy == "stripe")
        #expect(architecture.write(again) == written)
    }

    @Test func theReportWritesTheThirdParties() {
        drawTheModel()
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("## Third parties"))
        #expect(markdown.contains("[Stripe](https://stripe.com)"))
        #expect(markdown.contains("| SaaS | Yes | Hard |"))
        #expect(markdown.contains("Card numbers"))
        #expect(markdown.contains("No payment is taken while Stripe is down."))
    }

    /// The third parties read after the data inventory.
    @Test func theThirdPartiesComeAfterTheDataInventory() throws {
        drawTheModel()
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        let inventory = try #require(markdown.range(of: "## Data inventory"))
        let parties = try #require(markdown.range(of: "## Third parties"))
        #expect(inventory.lowerBound < parties.lowerBound)
    }

    @Test func theSummaryCountsWhatStopsTheSystem() {
        drawTheModel()
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("This system stops when 1 third party stops."))
    }

    @Test func aSystemWithNoThirdPartyWritesNoSection() {
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  component "api" {
                    technology = "aws-ec2"
                  }
                }

                """
            )
        )
        let markdown = app.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest()).markdown

        #expect(markdown.contains("## Third parties") == false)
        #expect(markdown.contains("third party stops") == false)
    }

    @Test func aSavedModelKeepsTheThirdParties() throws {
        let model = ThreatModel(
            name: "Payments",
            components: [
                Component(
                    id: ComponentId("checkout"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .internalData,
                    providedBy: "stripe"
                )
            ],
            thirdParties: [
                ThirdParty(
                    id: "stripe",
                    name: "Stripe",
                    kind: .saas,
                    payingCustomer: true,
                    uptime: .hard
                )
            ]
        )
        let codec = ThreatModelCodec()
        let read = try codec.decode(try codec.encode(model))

        #expect(read.thirdParties == model.thirdParties)
        #expect(read.components[0].providedBy == "stripe")
    }
}
