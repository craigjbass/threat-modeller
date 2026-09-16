import CommandLineApplication
import Testing
import ThreatModelKit
import TestSupport

/// What the actors list says about each actor a project may face.
@Suite("The threat actors a project may face")
struct ThreatActorsInUseTests {
    private let groups = """
    {
      "release": "v19.2",
      "groups": [
        {
          "id": "fin7",
          "attackId": "G0046",
          "name": "FIN7",
          "aliases": ["Carbon Spider"],
          "description": "A financially motivated threat group.",
          "techniques": ["T1552"],
          "techniquesViaSoftware": []
        },
        {
          "id": "quiet-crew",
          "attackId": "G0003",
          "name": "Quiet Crew",
          "aliases": [],
          "description": "",
          "techniques": ["T1499"],
          "techniquesViaSoftware": []
        }
      ]
    }
    """

    private func app(withGroups: Bool = false) -> TestDependencies {
        let app = TestDependencies()
        if withGroups {
            app.attackData.put(groups, fileName: AttackDataLocation.groupsFileName)
        }
        return app
    }

    private func listed(_ app: TestDependencies, mitreOnly: Bool = false) -> [ListedThreatActor] {
        app.listThreatActorsInUse()
            .execute(ListThreatActorsInUseRequest(mitreOnly: mitreOnly))
            .actors
    }

    private let contractor = ThreatActor(
        id: ThreatActorId("contractor"),
        name: "Third-party contractor",
        description: "A person who builds a part of the system and leaves.",
        capability: .targeted,
        intent: "financial",
        performs: [ThreatId("credential-theft")],
        techniques: ["T1552"]
    )

    @Test func statesTheCapabilityTheIntentAndTheThreatsAnActorPerforms() throws {
        let found = try #require(listed(app()).first { $0.id == "commodity-crimeware" })

        #expect(found.name == "Commodity crimeware")
        #expect(found.capabilityLabel == "Commodity")
        #expect(found.intent == "opportunistic")
        // The built-in actor states `performs_catalogue_tier = "commodity"`,
        // and every threat in the fixture catalogue is commodity.
        #expect(found.threatNames.contains("Credential Theft"))
        #expect(found.threatsPerformed == found.threatNames.count)
        #expect(found.threatsPerformed > 0)
    }

    @Test func namesTheMitreGroupsThatUseAnActorsTechniques() throws {
        let app = app(withGroups: true)
        app.modelStore.mutate { $0.localActors = [contractor] }

        let found = try #require(listed(app).first { $0.id == "contractor" })

        #expect(found.mitreGroups == ["FIN7"])
    }

    @Test func aMitreGroupStatesItself() throws {
        let app = app(withGroups: true)

        let found = try #require(listed(app).first { $0.id == "mitre-fin7" })

        #expect(found.mitreGroups == ["FIN7"])
    }

    @Test func aLocalBlockOverridesACatalogueActorWhole() throws {
        let app = app()
        app.modelStore.mutate {
            $0.localActors = [
                ThreatActor(
                    id: ThreatActorId("commodity-crimeware"),
                    name: "Our own crimeware",
                    capability: .research,
                    intent: "sabotage"
                )
            ]
        }

        let held = listed(app).filter { $0.id == "commodity-crimeware" }

        #expect(held.count == 1)
        #expect(held.first?.name == "Our own crimeware")
        #expect(held.first?.capabilityLabel == "Research")
        #expect(held.first?.isLocal == true)
        // The local block states no tier, so it performs nothing.
        #expect(held.first?.threatsPerformed == 0)
    }

    @Test func theActorsTheSystemFacesSortFirst() throws {
        let app = app()
        app.modelStore.mutate {
            $0.localActors = [self.contractor]
            $0.facedActorIds = ["contractor"]
        }

        let held = listed(app)

        #expect(held.first?.id == "contractor")
        #expect(held.first?.isFaced == true)
        #expect(held.first { $0.id == "commodity-crimeware" }?.isFaced == false)
    }

    @Test func theListSaysWhatTheExecutablePrints() {
        let app = app(withGroups: true)

        var printed: [String] = []
        _ = CommandLineApplication(
            projects: app.project,
            attackData: app.attackData,
            catalogue: { CatalogueFixture.catalogue() }
        )
        .run(
            arguments: ["threatmodeller", "actors", "list", "--mitre"],
            output: { printed.append($0) }
        )

        // The window reads the same use case, so the rows it draws say what
        // the verb prints, in the same order.
        let rows = listed(app, mitreOnly: true).map {
            "\($0.id)  \($0.name)  \($0.capabilityLabel)  \($0.threatsPerformed) threats"
        }
        #expect(rows == printed)
    }

    @Test func theMitreOnlyListHoldsTheGroupsAlone() {
        let app = app(withGroups: true)

        let held = listed(app, mitreOnly: true)

        #expect(held.allSatisfy { $0.id.hasPrefix("mitre-") })
        #expect(held.count == 2)
    }
}
