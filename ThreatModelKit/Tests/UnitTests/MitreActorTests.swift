import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// The ATT&CK groups on this machine, as threat actors.
@Suite("ATT&CK groups as threat actors")
struct MitreActorTests {
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
          "techniques": ["T1566", "credential-theft-technique"],
          "techniquesViaSoftware": ["T1078"]
        },
        {
          "id": "quiet-crew",
          "attackId": "G0003",
          "name": "Quiet Crew",
          "aliases": [],
          "description": "",
          "techniques": [],
          "techniquesViaSoftware": []
        }
      ]
    }
    """

    private func app(withData: Bool = true) -> TestDependencies {
        let app = TestDependencies()
        if withData {
            app.attackData.put(groups, fileName: AttackDataLocation.groupsFileName)
        }
        return app
    }

    @Test func everyGroupBecomesAnActor() throws {
        let app = app()

        let actor = try #require(app.catalogueInUse.findActor(ThreatActorId("mitre-fin7")))

        #expect(actor.name == "FIN7")
        #expect(actor.capability == .targeted)
        #expect(actor.aliases == ["Carbon Spider"])
        #expect(actor.techniques.contains("T1566"))
        #expect(actor.performs.isEmpty)
        #expect(actor.performsCatalogueTier == nil)
    }

    @Test func aGroupWithNoTechniquePerformsNothing() throws {
        let app = app()

        let actor = try #require(app.catalogueInUse.findActor(ThreatActorId("mitre-quiet-crew")))

        #expect(actor.techniques.isEmpty)
    }

    /// The files parse the first time something asks for a `mitre-` actor, and
    /// a project that faces none parses neither file.
    @Test func aProjectThatFacesNoGroupReadsNeitherFile() {
        let app = app()

        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  component "api" { technology = "aws-ec2" }
                }
                """
            )
        )
        _ = app.assessThreatModel().execute(AssessThreatModelRequest())

        #expect(app.attackData.reads.isEmpty)
    }

    @Test func askingForAGroupReadsTheFileOnce() {
        let app = app()

        _ = app.catalogueInUse.findActor(ThreatActorId("mitre-fin7"))
        _ = app.catalogueInUse.findActor(ThreatActorId("mitre-quiet-crew"))

        #expect(app.attackData.reads == [AttackDataLocation.groupsFileName])
    }

    /// A machine that has never synchronised reads zero groups, and the
    /// application starts.
    @Test func aMachineWithNoDataReadsZeroGroups() {
        let app = app(withData: false)

        #expect(app.catalogueInUse.findActor(ThreatActorId("mitre-fin7")) == nil)
        #expect(app.mitreActors.actors().isEmpty)
    }

    /// A `faces` entry naming a group nothing holds states so, and names the
    /// synchronise step.
    @Test func facingAGroupNothingHoldsNamesTheSynchroniseStep() {
        let app = app(withData: false)

        let response = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  faces = ["mitre-fin7"]

                  component "api" { technology = "aws-ec2" }
                }
                """
            )
        )

        // A `faces` entry naming nothing refuses the file: the diagram would
        // state an actor nobody holds.
        guard case .refused(let diagnostics) = response else {
            Issue.record("expected the file to be refused, got \(response)")
            return
        }
        let said = diagnostics.map(\.message).joined(separator: "\n")
        #expect(said.contains("mitre-fin7"))
        #expect(said.contains("threatmodeller attack sync"))
    }

    // MARK: the actors list

    @Test func listsTheGroupsAndHowMuchOfTheCatalogueEachTouches() throws {
        let app = app()

        let listed = app.listThreatActorsInUse()
            .execute(ListThreatActorsInUseRequest(mitreOnly: true))

        #expect(listed.actors.map(\.id).sorted() == ["mitre-fin7", "mitre-quiet-crew"])
        let fin7 = try #require(listed.actors.first { $0.id == "mitre-fin7" })
        #expect(fin7.capabilityLabel.isEmpty == false)
        #expect(fin7.threatsPerformed >= 0)
    }

    @Test func theListWithoutMitreHoldsTheCataloguesOwnActors() {
        let app = app()

        let listed = app.listThreatActorsInUse().execute(ListThreatActorsInUseRequest())

        #expect(listed.actors.contains { $0.id.hasPrefix("mitre-") })
        #expect(listed.actors.count > 2)
    }
}

/// What the report prints beside a technique id.
@Suite("The technique line in a report")
struct MitreReportLineTests {
    private let techniques = """
    {
      "release": "v19.2",
      "techniques": [
        {
          "id": "T1552",
          "name": "Unsecured Credentials",
          "tactics": ["credential-access"],
          "subtechnique": false
        }
      ]
    }
    """

    private func app(withData: Bool) -> TestDependencies {
        let app = TestDependencies()
        if withData {
            app.attackData.put(techniques, fileName: AttackDataLocation.techniquesFileName)
        }
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  component "api" {
                    technology = "aws-ec2"
                    data       = "confidential"
                  }
                }
                """
            )
        )
        return app
    }

    @Test func printsTheNameAndTheFirstTacticBesideTheId() {
        let markdown = app(withData: true).exportModelAsMarkdown()
            .execute(ExportModelAsMarkdownRequest()).markdown

        // The fixture catalogue names T1552 on credential theft.
        if markdown.contains("T1552") {
            #expect(markdown.contains("Unsecured Credentials (credential-access)"))
        }
    }

    /// GAP: a library threat's `mitre` block states a name and a tactic, and
    /// the report took the name from the synced bundle alone, so a machine
    /// that has not synchronised printed a bare id.
    @Test func printsTheLibrarySOwnNameWhenTheMachineHasNotSynchronised() {
        let markdown = app(withData: false).exportModelAsMarkdown()
            .execute(ExportModelAsMarkdownRequest()).markdown

        // The fixture catalogue names T1552 "Unsecured Credentials" on
        // credential theft, tactic "Credential Access".
        #expect(markdown.contains("Unsecured Credentials (Credential Access)"))
        #expect(markdown.contains("MITRE ATT&CK:"))
    }
}
