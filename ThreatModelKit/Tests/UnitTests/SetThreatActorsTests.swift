import Testing
import ThreatModelKit
import TestSupport

/// Writing the actors a system faces, and the actors it declares itself.
@Suite("Writing threat actors into the architecture")
struct SetThreatActorsTests {
    private func app() -> TestDependencies {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )
        return app
    }

    private func writeContractor(
        _ app: TestDependencies,
        name: String = "Third-party contractor",
        capability: String? = "targeted"
    ) -> SetLocalThreatActorResponse {
        app.setLocalThreatActor().execute(
            SetLocalThreatActorRequest(
                id: "contractor",
                name: name,
                description: "A person who builds a part of the system and leaves.",
                capability: capability,
                intent: "financial",
                performs: ["credential-theft"],
                techniques: ["T1552"]
            )
        )
    }

    // MARK: faces

    @Test func writesTheActorsTheSystemFaces() {
        let app = app()

        let response = app.setFacedThreatActors()
            .execute(SetFacedThreatActorsRequest(actorIds: ["commodity-crimeware"]))

        #expect(response == .recorded)
        #expect(app.modelStore.current().facedActorIds == ["commodity-crimeware"])
    }

    @Test func refusesAFacedIdNothingHolds() {
        let app = app()

        let response = app.setFacedThreatActors()
            .execute(SetFacedThreatActorsRequest(actorIds: ["nobody"]))

        #expect(response == .unknownActor("nobody"))
        #expect(app.modelStore.current().facedActorIds.isEmpty)
    }

    @Test func facesAnActorTheFileItselfDeclares() {
        let app = app()
        _ = writeContractor(app)

        let response = app.setFacedThreatActors()
            .execute(SetFacedThreatActorsRequest(actorIds: ["contractor"]))

        #expect(response == .recorded)
        #expect(app.modelStore.current().facedActorIds == ["contractor"])
    }

    // MARK: a local block

    @Test func writesALocalBlock() throws {
        let app = app()

        #expect(writeContractor(app) == .recorded)

        let actor = try #require(app.modelStore.current().localActors.first)
        #expect(actor.id == ThreatActorId("contractor"))
        #expect(actor.name == "Third-party contractor")
        #expect(actor.capability == .targeted)
        #expect(actor.intent == "financial")
        #expect(actor.performs == [ThreatId("credential-theft")])
        #expect(actor.techniques == ["T1552"])
    }

    @Test func changesTheBlockTheSameIdNames() throws {
        let app = app()
        _ = writeContractor(app)

        _ = writeContractor(app, name: "The contractor")

        #expect(app.modelStore.current().localActors.count == 1)
        #expect(app.modelStore.current().localActors.first?.name == "The contractor")
    }

    @Test func refusesABlockWithNoName() {
        let app = app()

        let response = writeContractor(app, name: "  ")

        #expect(response == .noName)
        #expect(app.modelStore.current().localActors.isEmpty)
    }

    @Test func dropsEmptyItemsAndTrimsWhitespaceFromEveryList() throws {
        let app = app()

        let response = app.setLocalThreatActor().execute(
            SetLocalThreatActorRequest(
                id: "contractor",
                name: "Third-party contractor",
                aliases: [" supplier ", "", "vendor"],
                capability: "targeted",
                intent: "financial",
                performs: ["credential-theft", " ", ""],
                techniques: ["T1552", " ", ""]
            )
        )

        #expect(response == .recorded)
        let actor = try #require(app.modelStore.current().localActors.first)
        #expect(actor.aliases == ["supplier", "vendor"])
        #expect(actor.performs == [ThreatId("credential-theft")])
        #expect(actor.techniques == ["T1552"])
    }

    @Test func writesAnInsiderCapability() throws {
        let app = app()

        #expect(writeContractor(app, capability: "insider") == .recorded)

        let actor = try #require(app.modelStore.current().localActors.first)
        #expect(actor.capability == .insider)
    }

    @Test func refusesACapabilityOutsideTheTiers() {
        let app = app()

        let response = writeContractor(app, capability: "worried")

        #expect(response == .unknownCapability)
        #expect(app.modelStore.current().localActors.isEmpty)
    }

    @Test func takesALocalBlockBackOffAndOutOfFaces() {
        let app = app()
        _ = writeContractor(app)
        _ = app.setFacedThreatActors()
            .execute(SetFacedThreatActorsRequest(actorIds: ["contractor", "commodity-crimeware"]))

        let response = app.removeLocalThreatActor()
            .execute(RemoveLocalThreatActorRequest(id: "contractor"))

        #expect(response == .removed)
        #expect(app.modelStore.current().localActors.isEmpty)
        #expect(app.modelStore.current().facedActorIds == ["commodity-crimeware"])
    }

    @Test func keepsAFacedIdTheCatalogueStillHolds() {
        let app = app()
        _ = app.setLocalThreatActor().execute(
            SetLocalThreatActorRequest(id: "commodity-crimeware", name: "Our own crimeware")
        )
        _ = app.setFacedThreatActors()
            .execute(SetFacedThreatActorsRequest(actorIds: ["commodity-crimeware"]))

        _ = app.removeLocalThreatActor()
            .execute(RemoveLocalThreatActorRequest(id: "commodity-crimeware"))

        // The catalogue holds an actor of that id, so the faces entry still
        // names one.
        #expect(app.modelStore.current().facedActorIds == ["commodity-crimeware"])
    }

    @Test func saysSoWhenNoLocalBlockHoldsThatId() {
        let app = app()

        let response = app.removeLocalThreatActor()
            .execute(RemoveLocalThreatActorRequest(id: "contractor"))

        #expect(response == .noSuchActor)
    }

    // MARK: the file

    @Test func writesFacesAndTheLocalBlockIntoTheArchitectureFile() throws {
        let app = app()
        _ = writeContractor(app)
        _ = app.setFacedThreatActors()
            .execute(SetFacedThreatActorsRequest(actorIds: ["contractor", "commodity-crimeware"]))

        let text = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(text.contains("faces"))
        #expect(text.contains("\"contractor\""))
        #expect(text.contains("threat_actor \"contractor\""))

        // The file reads back as the model that wrote it.
        let read = TestDependencies()
        let response = read.importArchitecture().execute(ImportArchitectureRequest(text: text))
        guard case .imported = response else {
            Issue.record("expected the file to import, got \(response)")
            return
        }
        #expect(read.modelStore.current().facedActorIds == ["contractor", "commodity-crimeware"])
        let actor = try #require(read.modelStore.current().localActors.first)
        #expect(actor.id == ThreatActorId("contractor"))
        #expect(actor.capability == .targeted)
        #expect(actor.techniques == ["T1552"])
    }
}
