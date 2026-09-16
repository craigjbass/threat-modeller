import Testing
import ThreatModelKit
import TestSupport

/// Writing what a system states about itself: its owner, its description, its
/// authors, its version, the day it was written, the day it was last read
/// again, its links, its repositories and its free-form attributes.
@Suite("Writing a system's document-control facts")
struct SetSystemFactsTests {
    private func app() -> TestDependencies {
        let app = TestDependencies()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        )
        return app
    }

    // MARK: one field at a time

    @Test func writesTheOwner() {
        let app = app()

        #expect(app.setSystemFacts().execute(SetSystemFactsRequest(owner: "Payments team")) == .recorded)

        #expect(app.modelStore.current().owner == "Payments team")
    }

    @Test func writesTheDescription() {
        let app = app()

        #expect(
            app.setSystemFacts()
                .execute(SetSystemFactsRequest(description: "Takes the card payments."))
                == .recorded
        )

        #expect(app.modelStore.current().documentFacts.description == "Takes the card payments.")
    }

    @Test func writesTheAuthors() {
        let app = app()

        #expect(
            app.setSystemFacts()
                .execute(SetSystemFactsRequest(authors: ["Ada Lovelace", "Alan Turing"]))
                == .recorded
        )

        #expect(app.modelStore.current().documentFacts.authors == ["Ada Lovelace", "Alan Turing"])
    }

    @Test func writesTheVersion() {
        let app = app()

        #expect(app.setSystemFacts().execute(SetSystemFactsRequest(version: "1.2")) == .recorded)

        #expect(app.modelStore.current().documentFacts.version == "1.2")
    }

    @Test func writesTheCreatedDate() {
        let app = app()

        #expect(
            app.setSystemFacts().execute(SetSystemFactsRequest(created: "2026-01-04")) == .recorded
        )

        #expect(app.modelStore.current().documentFacts.created == "2026-01-04")
    }

    @Test func writesTheReviewedDate() {
        let app = app()

        #expect(
            app.setSystemFacts().execute(SetSystemFactsRequest(reviewed: "2026-09-16")) == .recorded
        )

        #expect(app.modelStore.current().documentFacts.reviewed == "2026-09-16")
    }

    @Test func writesTheLinks() {
        let app = app()

        #expect(
            app.setSystemFacts()
                .execute(SetSystemFactsRequest(links: ["https://wiki.example/payments"]))
                == .recorded
        )

        #expect(app.modelStore.current().documentFacts.links == ["https://wiki.example/payments"])
    }

    @Test func writesTheRepositories() {
        let app = app()

        #expect(
            app.setSystemFacts()
                .execute(SetSystemFactsRequest(repositories: ["https://github.example/payments"]))
                == .recorded
        )

        #expect(
            app.modelStore.current().documentFacts.repositories
                == ["https://github.example/payments"]
        )
    }

    // MARK: a field nobody sent

    @Test func leavesEveryFieldTheRequestDoesNotName() {
        let app = app()
        _ = app.setSystemFacts().execute(
            SetSystemFactsRequest(
                owner: "Payments team",
                description: "Takes the card payments.",
                authors: ["Ada Lovelace"],
                version: "1.2",
                created: "2026-01-04",
                reviewed: "2026-09-16",
                links: ["https://wiki.example/payments"],
                repositories: ["https://github.example/payments"]
            )
        )

        #expect(app.setSystemFacts().execute(SetSystemFactsRequest(version: "1.3")) == .recorded)

        let model = app.modelStore.current()
        #expect(model.owner == "Payments team")
        #expect(model.documentFacts.description == "Takes the card payments.")
        #expect(model.documentFacts.authors == ["Ada Lovelace"])
        #expect(model.documentFacts.version == "1.3")
        #expect(model.documentFacts.created == "2026-01-04")
        #expect(model.documentFacts.reviewed == "2026-09-16")
        #expect(model.documentFacts.links == ["https://wiki.example/payments"])
        #expect(model.documentFacts.repositories == ["https://github.example/payments"])
    }

    @Test func clearsAnAttributeAnEmptyValueNames() {
        let app = app()
        _ = app.setSystemFacts().execute(SetSystemFactsRequest(authors: ["Ada"], version: "1.2"))

        _ = app.setSystemFacts().execute(SetSystemFactsRequest(authors: [], version: ""))

        #expect(app.modelStore.current().documentFacts.version == "")
        #expect(app.modelStore.current().documentFacts.authors.isEmpty)
    }

    @Test func dropsTheWhitespaceAroundEveryValue() {
        let app = app()

        _ = app.setSystemFacts().execute(
            SetSystemFactsRequest(
                owner: "  Payments team  ",
                authors: [" Ada Lovelace ", "  ", "Alan Turing"]
            )
        )

        #expect(app.modelStore.current().owner == "Payments team")
        #expect(app.modelStore.current().documentFacts.authors == ["Ada Lovelace", "Alan Turing"])
    }

    // MARK: a date that is not a date

    @Test func refusesACreatedDateThatIsNotADate() {
        let app = app()
        _ = app.setSystemFacts().execute(SetSystemFactsRequest(created: "2026-01-04"))

        #expect(
            app.setSystemFacts().execute(SetSystemFactsRequest(created: "yesterday"))
                == .notADate("created")
        )

        #expect(app.modelStore.current().documentFacts.created == "2026-01-04")
    }

    @Test func refusesAReviewedDateThatIsNotADay() {
        let app = app()

        #expect(
            app.setSystemFacts().execute(SetSystemFactsRequest(reviewed: "2026-02-30"))
                == .notADate("reviewed")
        )

        #expect(app.modelStore.current().documentFacts.reviewed == "")
    }

    @Test func writesNothingAtAllWhenOneDateIsNotADate() {
        let app = app()

        _ = app.setSystemFacts().execute(
            SetSystemFactsRequest(owner: "Payments team", created: "the fourth of January")
        )

        #expect(app.modelStore.current().owner == "")
    }

    @Test func saysWhyADateIsRefused() {
        var message: String?
        SetSystemFactsResponse.notADate("reviewed").describe(into: &message)

        #expect(message == "The reviewed date is written YYYY-MM-DD.")
    }

    // MARK: free-form attribute blocks

    @Test func writesAnAttributeBlock() throws {
        let app = app()

        #expect(
            app.setSystemAttribute()
                .execute(SetSystemAttributeRequest(name: "service_tier", value: "gold"))
                == .recorded
        )

        let attribute = try #require(app.modelStore.current().documentFacts.attributes.first)
        #expect(attribute.name == "service_tier")
        #expect(attribute.value == "gold")
    }

    @Test func writesTheSameAttributeNameAgainToChangeItsValue() {
        let app = app()
        _ = app.setSystemAttribute()
            .execute(SetSystemAttributeRequest(name: "service_tier", value: "gold"))

        _ = app.setSystemAttribute()
            .execute(SetSystemAttributeRequest(name: "service_tier", value: "silver"))

        let attributes = app.modelStore.current().documentFacts.attributes
        #expect(attributes.count == 1)
        #expect(attributes[0].value == "silver")
    }

    @Test func refusesAnAttributeWithNoName() {
        let app = app()

        #expect(
            app.setSystemAttribute().execute(SetSystemAttributeRequest(name: "  ", value: "gold"))
                == .noName
        )

        #expect(app.modelStore.current().documentFacts.attributes.isEmpty)
    }

    @Test func takesAnAttributeBlockOff() {
        let app = app()
        _ = app.setSystemAttribute()
            .execute(SetSystemAttributeRequest(name: "service_tier", value: "gold"))

        #expect(
            app.removeSystemAttribute().execute(RemoveSystemAttributeRequest(name: "service_tier"))
                == .removed
        )

        #expect(app.modelStore.current().documentFacts.attributes.isEmpty)
    }

    @Test func refusesToTakeOffAnAttributeTheSystemDoesNotState() {
        let app = app()

        #expect(
            app.removeSystemAttribute().execute(RemoveSystemAttributeRequest(name: "nothing"))
                == .noSuchAttribute
        )
    }

    // MARK: what the interface reads

    @Test func theViewStatesEveryFact() throws {
        let app = app()
        _ = app.setSystemFacts().execute(
            SetSystemFactsRequest(
                owner: "Payments team",
                description: "Takes the card payments.",
                authors: ["Ada Lovelace"],
                version: "1.2",
                created: "2026-01-04",
                reviewed: "2026-09-16",
                links: ["https://wiki.example/payments"],
                repositories: ["https://github.example/payments"]
            )
        )
        _ = app.setSystemAttribute()
            .execute(SetSystemAttributeRequest(name: "service_tier", value: "gold"))

        let facts = app.viewThreatModel().execute(ViewThreatModelRequest()).systemFacts

        #expect(facts.owner == "Payments team")
        #expect(facts.description == "Takes the card payments.")
        #expect(facts.authors == ["Ada Lovelace"])
        #expect(facts.version == "1.2")
        #expect(facts.created == "2026-01-04")
        #expect(facts.reviewed == "2026-09-16")
        #expect(facts.links == ["https://wiki.example/payments"])
        #expect(facts.repositories == ["https://github.example/payments"])
        let attribute = try #require(facts.attributes.first)
        #expect(attribute.name == "service_tier")
        #expect(attribute.value == "gold")
    }

    // MARK: the Edit menu

    @Test func namesTheChangeForTheEditMenu() {
        let app = app()

        _ = app.setSystemFacts().execute(SetSystemFactsRequest(owner: "Payments team"))

        #expect(app.modelStore.undoLabel == ChangeLabel.setSystemFacts)
    }
}
