import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Reading and writing the third parties in the window, end to end: the list
/// the assumptions panel draws, the `third_party` blocks the save writes, and
/// the `provided_by` the component panel picks.
@MainActor
@Suite("Third parties in the window")
struct ThirdPartyEditorFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private let withStripe = """
    system "Payments" {
      third_party "stripe" {
        name            = "Stripe"
        description     = "Takes the card payments."
        kind            = "saas"
        paying_customer = true
        uptime          = "hard"
        uptime_notes    = "No payment runs while Stripe is down."
        owner           = "Payments team"
        link            = "https://stripe.com"
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject(_ text: String? = nil) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(text ?? payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func architecture(_ useCases: TestDependencies) -> String? {
        useCases.project.text(at: "/work/threatmodel/payments.arch")
    }

    private func writeStripe(_ model: ThreatModelSession, name: String = "Stripe") {
        model.setThirdParty(
            id: "stripe",
            name: name,
            description: "Takes the card payments.",
            kindId: "saas",
            payingCustomer: true,
            uptimeId: "hard",
            uptimeNotes: "No payment runs while Stripe is down.",
            owner: "Payments team",
            link: "https://stripe.com"
        )
    }

    // MARK: the list

    @Test func listsEveryThirdPartyTheFileStates() async throws {
        let (session, _) = await aProject(withStripe)
        let model = try #require(session.model)

        let party = try #require(model.canvas.thirdParties.first)
        #expect(party.id == "stripe")
        #expect(party.name == "Stripe")
        #expect(party.description == "Takes the card payments.")
        #expect(party.kindId == "saas")
        #expect(party.kindLabel == "SaaS")
        #expect(party.payingCustomer)
        #expect(party.uptimeId == "hard")
        #expect(party.uptimeLabel == "Hard")
        #expect(party.uptimeNotes == "No payment runs while Stripe is down.")
        #expect(party.owner == "Payments team")
        #expect(party.link == "https://stripe.com")
    }

    // MARK: writing a block

    @Test func writesAThirdPartyIntoTheFile() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        writeStripe(model)
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("third_party \"stripe\""))
        #expect(written.contains("\"Stripe\""))
        #expect(written.contains("paying_customer"))
        #expect(written.contains("\"hard\""))
        #expect(written.contains("No payment runs while Stripe is down."))
        #expect(written.contains("\"Payments team\""))
        #expect(written.contains("https://stripe.com"))
    }

    @Test func writesTheBlockAndLeavesEveryOtherBlockWhereItWas() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        // A save with nothing changed, so the two texts differ by the party's
        // own lines alone and by nothing the writer normalises.
        await session.save()
        let before = try #require(architecture(useCases))

        writeStripe(model)
        await session.save()
        let after = try #require(architecture(useCases))

        #expect(model.errorMessage == nil)
        #expect(after != before)
        #expect(
            Self.holdsEveryLine(of: before, inOrder: after),
            "the write moved or dropped a line the file already held"
        )

        model.removeThirdParty(id: "stripe")
        await session.save()

        #expect(architecture(useCases) == before)
    }

    /// True when every line of `before` is in `after`, in the same order. A
    /// new block adds lines; it must change none of the lines around it.
    private static func holdsEveryLine(of before: String, inOrder after: String) -> Bool {
        var wanted = before.split(separator: "\n", omittingEmptySubsequences: true)[...]
        for line in after.split(separator: "\n", omittingEmptySubsequences: true) {
            if wanted.first == line { wanted = wanted.dropFirst() }
        }
        return wanted.isEmpty
    }

    @Test func changesAThirdPartyThatIsAlreadyThere() async throws {
        let (session, useCases) = await aProject(withStripe)
        let model = try #require(session.model)

        writeStripe(model, name: "Stripe Payments")
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(model.canvas.thirdParties.count == 1)
        let written = try #require(architecture(useCases))
        #expect(written.contains("\"Stripe Payments\""))
    }

    @Test func takesAThirdPartyOffTheFile() async throws {
        let (session, useCases) = await aProject(withStripe)
        let model = try #require(session.model)

        model.removeThirdParty(id: "stripe")
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("third_party \"stripe\"") == false)
    }

    @Test func theParserReadsTheBlockBackWithTheSameFields() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        writeStripe(model)
        await session.save()

        let text = try #require(architecture(useCases))
        let source = try #require(HclArchitectureSource().read(text).source)
        let party = try #require(source.thirdParties.first)
        #expect(party.id == "stripe")
        #expect(party.name == "Stripe")
        #expect(party.description == "Takes the card payments.")
        #expect(party.kind == "saas")
        #expect(party.payingCustomer)
        #expect(party.uptime == "hard")
        #expect(party.uptimeNotes == "No payment runs while Stripe is down.")
        #expect(party.owner == "Payments team")
        #expect(party.link == "https://stripe.com")
    }

    // MARK: the Provided by picker

    @Test func thePickWritesProvidedByToTheFile() async throws {
        let (session, useCases) = await aProject(withStripe)
        let model = try #require(session.model)
        let component = try #require(model.canvas.components.first)

        model.setComponentProvider(componentId: component.id, thirdPartyId: "stripe")
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("provided_by = \"stripe\""))
        let source = try #require(HclArchitectureSource().read(written).source)
        #expect(source.components[0].providedBy == "stripe")
    }

    @Test func theComponentPanelListsTheThirdParties() async throws {
        let (session, _) = await aProject(withStripe)
        let model = try #require(session.model)
        let component = try #require(model.canvas.components.first)

        let panel = ComponentPanel(session: model, component: component)

        #expect(panel.providerChoices.map(\.id) == ["", "stripe"])
        #expect(panel.providerChoices.map(\.label) == ["Provided by nobody", "Stripe"])
    }

    @Test func thePickComesBackOffAgain() async throws {
        let (session, useCases) = await aProject(withStripe)
        let model = try #require(session.model)
        let component = try #require(model.canvas.components.first)
        model.setComponentProvider(componentId: component.id, thirdPartyId: "stripe")

        model.setComponentProvider(componentId: component.id, thirdPartyId: nil)
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("provided_by") == false)
    }

    // MARK: refusing a removal a component depends on

    @Test func refusesToRemoveAThirdPartyAComponentNames() async throws {
        let (session, _) = await aProject(withStripe)
        let model = try #require(session.model)
        let component = try #require(model.canvas.components.first)
        model.setComponentProvider(componentId: component.id, thirdPartyId: "stripe")

        model.removeThirdParty(id: "stripe")

        #expect(
            model.errorMessage == "The component \"EC2\" states this third party provides it."
        )
        #expect(model.canvas.thirdParties.count == 1)
    }

    // MARK: the report

    @Test func aReportBuiltAfterTheWriteListsTheThirdParty() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        writeStripe(model)
        await session.save()

        let report = useCases.buildThreatModelReport()
            .execute(BuildThreatModelReportRequest()).report
        let party = try #require(report.thirdParties.first)
        #expect(party.name == "Stripe")
        #expect(party.uptimeLabel == "Hard")
    }

    // MARK: the sheet

    /// #145: the third-party editor left the architecture sidebar for the
    /// Third Parties sheet the System menu opens, so the drawing test draws
    /// the sheet.
    @Test func theThirdPartiesSheetDraws() async throws {
        let (session, _) = await aProject(withStripe)
        let model = try #require(session.model)

        let renderer = ImageRenderer(
            content: ThirdPartiesSheet(session: model, dismiss: {}).frame(width: 760, height: 520)
        )
        renderer.scale = 1

        #expect(renderer.cgImage != nil)
    }
}
