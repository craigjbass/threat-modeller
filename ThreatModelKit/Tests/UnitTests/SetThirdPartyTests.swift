import Testing
import ThreatModelKit
import TestSupport

/// Writing the parties outside this team the system depends on, and naming
/// the party that provides one component.
@Suite("Writing third parties into the architecture")
struct SetThirdPartyTests {
    private func app() -> TestDependencies {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )
        return app
    }

    private func componentId(_ app: TestDependencies) -> String {
        app.modelStore.current().components[0].id.value
    }

    @discardableResult
    private func writeStripe(
        _ app: TestDependencies,
        name: String = "Stripe",
        kind: String = "saas",
        uptime: String = "hard"
    ) -> SetThirdPartyResponse {
        app.setThirdParty().execute(
            SetThirdPartyRequest(
                id: "stripe",
                name: name,
                description: "Takes the card payments.",
                kind: kind,
                payingCustomer: true,
                uptime: uptime,
                uptimeNotes: "No payment runs while Stripe is down.",
                owner: "Payments team",
                link: "https://stripe.com"
            )
        )
    }

    // MARK: writing a block

    @Test func writesAThirdParty() throws {
        let app = app()

        #expect(writeStripe(app) == .recorded)

        let party = try #require(app.modelStore.current().thirdParties.first)
        #expect(party.id == "stripe")
        #expect(party.name == "Stripe")
        #expect(party.description == "Takes the card payments.")
        #expect(party.kind == .saas)
        #expect(party.payingCustomer)
        #expect(party.uptime == .hard)
        #expect(party.uptimeNotes == "No payment runs while Stripe is down.")
        #expect(party.owner == "Payments team")
        #expect(party.link == "https://stripe.com")
    }

    @Test func writesTheSameIdAgainToChangeTheBlock() throws {
        let app = app()
        writeStripe(app)

        #expect(writeStripe(app, name: "Stripe Payments", uptime: "degraded") == .recorded)

        let parties = app.modelStore.current().thirdParties
        #expect(parties.count == 1)
        #expect(parties[0].name == "Stripe Payments")
        #expect(parties[0].uptime == .degraded)
    }

    @Test func refusesAThirdPartyWithNoIdentifier() {
        let app = app()

        let response = app.setThirdParty().execute(
            SetThirdPartyRequest(id: "  ", name: "Stripe", uptime: "none")
        )

        #expect(response == .noId)
        #expect(app.modelStore.current().thirdParties.isEmpty)
    }

    @Test func refusesAThirdPartyWithNoName() {
        let app = app()

        let response = app.setThirdParty().execute(
            SetThirdPartyRequest(id: "stripe", name: " ", uptime: "none")
        )

        #expect(response == .noName)
        #expect(app.modelStore.current().thirdParties.isEmpty)
    }

    @Test func refusesAKindTheLanguageDoesNotHold() {
        let app = app()

        #expect(writeStripe(app, kind: "vendor") == .unknownKind)
        #expect(app.modelStore.current().thirdParties.isEmpty)
    }

    @Test func refusesAnUptimeTheLanguageDoesNotHold() {
        let app = app()

        #expect(writeStripe(app, uptime: "total") == .unknownUptime)
        #expect(app.modelStore.current().thirdParties.isEmpty)
    }

    @Test func takesAnEmptyOwnerAndLinkAsNothing() throws {
        let app = app()

        _ = app.setThirdParty().execute(
            SetThirdPartyRequest(id: "stripe", name: "Stripe", uptime: "none", owner: " ", link: "")
        )

        let party = try #require(app.modelStore.current().thirdParties.first)
        #expect(party.owner == nil)
        #expect(party.link == nil)
    }

    // MARK: taking a block off

    @Test func takesAThirdPartyOff() {
        let app = app()
        writeStripe(app)

        let response = app.removeThirdParty().execute(RemoveThirdPartyRequest(id: "stripe"))

        #expect(response == .removed)
        #expect(app.modelStore.current().thirdParties.isEmpty)
    }

    @Test func saysSoWhenNoSuchThirdPartyIsThere() {
        let app = app()

        let response = app.removeThirdParty().execute(RemoveThirdPartyRequest(id: "stripe"))

        #expect(response == .noSuchThirdParty)
    }

    @Test func refusesToTakeOffAThirdPartyAComponentNames() {
        let app = app()
        writeStripe(app)
        let component = componentId(app)
        _ = app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: component,
                name: "Payments API",
                sensitivity: "internal",
                threatsDisabled: false,
                runsAs: "user"
            )
        )
        _ = app.setComponentProvider().execute(
            SetComponentProviderRequest(componentId: component, thirdPartyId: "stripe")
        )

        let response = app.removeThirdParty().execute(RemoveThirdPartyRequest(id: "stripe"))

        #expect(response == .providesComponent("Payments API"))
        #expect(app.modelStore.current().thirdParties.count == 1)
    }

    @Test func theRefusalNamesTheComponent() {
        var message: String?

        RemoveThirdPartyResponse.providesComponent("Payments API").describe(into: &message)

        #expect(message == "The component \"Payments API\" states this third party provides it.")
    }

    // MARK: naming the party that provides a component

    @Test func namesThePartyThatProvidesAComponent() {
        let app = app()
        writeStripe(app)
        let component = componentId(app)

        let response = app.setComponentProvider().execute(
            SetComponentProviderRequest(componentId: component, thirdPartyId: "stripe")
        )

        #expect(response == .updated)
        #expect(app.modelStore.current().components[0].providedBy == "stripe")
    }

    @Test func takesThePartyBackOffAComponent() {
        let app = app()
        writeStripe(app)
        let component = componentId(app)
        _ = app.setComponentProvider().execute(
            SetComponentProviderRequest(componentId: component, thirdPartyId: "stripe")
        )

        let response = app.setComponentProvider().execute(
            SetComponentProviderRequest(componentId: component, thirdPartyId: nil)
        )

        #expect(response == .updated)
        #expect(app.modelStore.current().components[0].providedBy == nil)
    }

    @Test func refusesAPartyTheSystemDoesNotDeclare() {
        let app = app()
        let component = componentId(app)

        let response = app.setComponentProvider().execute(
            SetComponentProviderRequest(componentId: component, thirdPartyId: "stripe")
        )

        #expect(response == .unknownThirdParty)
        #expect(app.modelStore.current().components[0].providedBy == nil)
    }

    @Test func refusesAComponentTheSystemDoesNotHold() {
        let app = app()
        writeStripe(app)

        let response = app.setComponentProvider().execute(
            SetComponentProviderRequest(componentId: "nobody", thirdPartyId: "stripe")
        )

        #expect(response == .unknownComponent)
    }

    // MARK: what the window reads

    @Test func theViewListsTheThirdParties() throws {
        let app = app()
        writeStripe(app)
        let component = componentId(app)
        _ = app.setComponentProvider().execute(
            SetComponentProviderRequest(componentId: component, thirdPartyId: "stripe")
        )

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())

        let party = try #require(view.thirdParties.first)
        #expect(party.id == "stripe")
        #expect(party.name == "Stripe")
        #expect(party.kindId == "saas")
        #expect(party.payingCustomer)
        #expect(party.uptimeId == "hard")
        #expect(party.uptimeNotes == "No payment runs while Stripe is down.")
        #expect(party.owner == "Payments team")
        #expect(party.link == "https://stripe.com")
        #expect(view.components[0].providedById == "stripe")
    }
}
