import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Reading and writing the threat actors in the window, end to end: the list
/// the sheet draws, the `faces` line the save writes, and the local
/// `threat_actor` block.
@MainActor
@Suite("Threat actors in the window")
struct ThreatActorEditorFlowTests {
    private let payments = """
    system "Payments" {
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

    // MARK: the list

    @Test func listsTheActorsTheProjectMayFace() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        let crimeware = try #require(
            model.threatActorsInUse.first { $0.id == "commodity-crimeware" }
        )
        #expect(crimeware.capabilityLabel == "Commodity")
        #expect(crimeware.intent == "opportunistic")
        #expect(crimeware.threatNames.isEmpty == false)
        #expect(crimeware.isFaced == false)
    }

    @Test func statesWhichActorsTheFileAlreadyFaces() async throws {
        let (session, _) = await aProject("""
        system "Payments" {
          faces = ["contractor"]

          threat_actor "contractor" {
            name       = "Third-party contractor"
            capability = "targeted"
            intent     = "financial"
            performs   = ["credential-theft"]
          }

          component "api" {
            technology = "aws-ec2"
          }
        }

        """)
        let model = try #require(session.model)

        let contractor = try #require(
            model.threatActorsInUse.first { $0.id == "contractor" }
        )
        #expect(contractor.isFaced)
        #expect(contractor.isLocal)
        #expect(contractor.threatNames == ["Credential Theft"])
        // The faced actors sort first.
        #expect(model.threatActorsInUse.first?.id == "contractor")
    }

    // MARK: writing faces

    @Test func writesTheFacesListIntoTheFile() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setFacedThreatActors(["commodity-crimeware"])
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("faces"))
        #expect(written.contains("commodity-crimeware"))
    }

    @Test func saysSoWhenTheProjectHoldsNoSuchActor() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        model.setFacedThreatActors(["nobody"])

        #expect(model.errorMessage == "This project holds no threat actor called \"nobody\".")
        #expect(model.threatActorsInUse.contains { $0.isFaced } == false)
    }

    // MARK: writing a local block

    @Test func writesALocalBlockIntoTheFileAndFacesIt() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setLocalThreatActor(
            id: "contractor",
            name: "Third-party contractor",
            description: "A person who builds a part of the system and leaves.",
            capability: "targeted",
            intent: "financial",
            performs: ["credential-theft"],
            techniques: ["T1552"]
        )
        model.setFacedThreatActors(["contractor"])
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("threat_actor \"contractor\""))
        // The writer lines the values up, so the attribute reads with two spaces.
        #expect(written.contains("capability  = \"targeted\""))
        #expect(written.contains("faces"))
    }

    @Test func takesALocalBlockBackOff() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        model.setLocalThreatActor(id: "contractor", name: "Third-party contractor")
        model.setFacedThreatActors(["contractor"])

        model.removeLocalThreatActor(id: "contractor")
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("threat_actor \"contractor\"") == false)
        #expect(written.contains("faces") == false)
    }

    @Test func writesFacesAndLeavesEveryOtherBlockWhereItWas() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        // A save with nothing changed, so the two texts differ by the faces
        // line alone and by nothing the writer normalises.
        await session.save()
        let before = try #require(architecture(useCases))

        model.setFacedThreatActors(["commodity-crimeware"])
        await session.save()

        let after = try #require(architecture(useCases))
        let lines = after.split(separator: "\n", omittingEmptySubsequences: true)
        let added = lines.filter { $0.contains("faces") }
        #expect(added.count == 1)
        #expect(
            lines.filter { $0.contains("faces") == false }
                == before.split(separator: "\n", omittingEmptySubsequences: true)
        )
    }

    @Test func theParserReadsTheLocalBlockBackWithTheSameFields() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setLocalThreatActor(
            id: "contractor",
            name: "Third-party contractor",
            description: "A person who builds a part of the system and leaves.",
            aliases: ["supplier"],
            capability: "targeted",
            intent: "financial",
            performs: ["credential-theft"],
            techniques: ["T1552"]
        )
        await session.save()

        let text = try #require(architecture(useCases))
        let source = try #require(HclArchitectureSource().read(text).source)
        let actor = try #require(source.threatActors.first)
        #expect(actor.id == "contractor")
        #expect(actor.name == "Third-party contractor")
        #expect(actor.description == "A person who builds a part of the system and leaves.")
        #expect(actor.aliases == ["supplier"])
        #expect(actor.capability == "targeted")
        #expect(actor.intent == "financial")
        #expect(actor.performs == ["credential-theft"])
        #expect(actor.techniques == ["T1552"])
    }

    // MARK: the aliases the sheet carries

    /// #163: the sheet had no aliases field, so editing an actor through it
    /// dropped whatever aliases the file already held.
    @Test func editingAnActorThroughTheSheetKeepsItsAliases() async throws {
        let (session, useCases) = await aProject("""
        system "Payments" {
          faces = ["contractor"]

          threat_actor "contractor" {
            name       = "Third-party contractor"
            aliases    = ["supplier", "vendor"]
            capability = "targeted"
            intent     = "financial"
            performs   = ["credential-theft"]
          }

          component "api" {
            technology = "aws-ec2"
          }
        }

        """)
        let model = try #require(session.model)

        // Read the actor into the form the way the pencil button does, then
        // change the intent alone. The aliases the read carried over must
        // still write, because the sheet never cleared them.
        let actor = try #require(model.threatActorsInUse.first { $0.id == "contractor" })
        let sheet = ThreatActorsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: actor.id,
                name: actor.name,
                description: actor.description,
                aliases: actor.aliases.joined(separator: ", "),
                capability: actor.capabilityId,
                intent: "commercial",
                performs: actor.performsThreatIds.joined(separator: ", "),
                techniques: actor.techniques
            )
        )
        sheet.write()
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        let source = try #require(HclArchitectureSource().read(written).source)
        let contractor = try #require(source.threatActors.first { $0.id == "contractor" })
        #expect(contractor.intent == "commercial")
        #expect(contractor.aliases == ["supplier", "vendor"])
    }

    // MARK: a trailing comma writes no empty id

    /// #232: `ThreatActorsSheet` reads its comma-separated fields through
    /// `SystemSheetWriting.split(_:)`, so a trailing comma drops the empty
    /// item it would otherwise leave.
    @Test func aTrailingCommaInTheAliasesFieldWritesNoEmptyId() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        let sheet = ThreatActorsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: "contractor",
                name: "Third-party contractor",
                aliases: "supplier, vendor,",
                capability: "targeted",
                intent: "financial",
                performs: "credential-theft"
            )
        )
        sheet.write()
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        let source = try #require(HclArchitectureSource().read(written).source)
        let contractor = try #require(source.threatActors.first { $0.id == "contractor" })
        #expect(contractor.aliases == ["supplier", "vendor"])
        #expect(contractor.aliases.contains("") == false)
    }

    @Test func aTrailingCommaInThePerformsFieldWritesNoEmptyId() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        let sheet = ThreatActorsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: "contractor",
                name: "Third-party contractor",
                capability: "targeted",
                intent: "financial",
                performs: "credential-theft, malware-deployment,"
            )
        )
        sheet.write()
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        let source = try #require(HclArchitectureSource().read(written).source)
        let contractor = try #require(source.threatActors.first { $0.id == "contractor" })
        #expect(contractor.performs == ["credential-theft", "malware-deployment"])
        #expect(contractor.performs.contains("") == false)
    }

    /// The technique ids come from a search-and-pick control, not a
    /// comma-separated line, but the file still holds no empty id: a commit
    /// with nothing typed adds nothing.
    @Test func theTechniquesFieldWritesNoEmptyId() async throws {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.attackData.put(
            Self.techniques,
            fileName: AttackDataLocation.techniquesFileName
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        let model = try #require(session.model)

        let held = MitreIdFieldTests.Held()
        let field = ThreatActorsSheet(session: model, dismiss: {})
            .techniqueField(held.binding)
        field.pick(try #require(field.rows(for: "exploit pub").first))
        field.pick(try #require(field.rows(for: "valid acc").first))
        field.commitTyped()
        #expect(held.ids == ["T1190", "T1078"])

        let sheet = ThreatActorsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: "contractor",
                name: "Third-party contractor",
                capability: "targeted",
                techniques: held.ids
            )
        )
        sheet.write()
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        let source = try #require(HclArchitectureSource().read(written).source)
        let actor = try #require(source.threatActors.first { $0.id == "contractor" })
        #expect(actor.techniques == ["T1190", "T1078"])
        #expect(actor.techniques.contains("") == false)
    }

    // MARK: the techniques picked through the MITRE id field

    /// The ATT&CK data this machine holds, for the field to search.
    private static let techniques = """
    {
      "release": "v19.2",
      "techniques": [
        {
          "id": "T1190",
          "name": "Exploit Public-Facing Application",
          "tactics": ["initial-access"],
          "subtechnique": false
        },
        {
          "id": "T1078",
          "name": "Valid Accounts",
          "tactics": ["defense-evasion"],
          "subtechnique": false
        }
      ]
    }
    """

    /// #148: a person picks two techniques out of the synchronised matrix and
    /// the file holds the same `techniques` list the parser reads.
    @Test func writesTheTechniquesPickedThroughTheMitreIdField() async throws {
        // The matrix is on this machine before the project opens, the way it
        // is for a person who synchronised on another day.
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.attackData.put(
            Self.techniques,
            fileName: AttackDataLocation.techniquesFileName
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        let model = try #require(session.model)

        // The control the sheet draws, writing into the list the form holds.
        let held = MitreIdFieldTests.Held()
        let field = ThreatActorsSheet(session: model, dismiss: {})
            .techniqueField(held.binding)
        field.pick(try #require(field.rows(for: "exploit pub").first))
        field.pick(try #require(field.rows(for: "valid acc").first))
        #expect(held.ids == ["T1190", "T1078"])

        let sheet = ThreatActorsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: "contractor",
                name: "Third-party contractor",
                capability: "targeted",
                techniques: held.ids
            )
        )
        sheet.write()
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("[\"T1190\", \"T1078\"]"))
        let source = try #require(HclArchitectureSource().read(written).source)
        let actor = try #require(source.threatActors.first { $0.id == "contractor" })
        #expect(actor.techniques == ["T1190", "T1078"])
    }

    // MARK: what the threat card reads

    @Test func theThreatCardNamesTheActorThatPerformsTheThreat() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        model.setLocalThreatActor(
            id: "contractor",
            name: "Third-party contractor",
            capability: "targeted",
            performs: ["credential-theft"]
        )

        model.setFacedThreatActors(["contractor"])

        let threat = try #require(model.threats.first { $0.threatId == "credential-theft" })
        #expect(threat.performedByLabels == ["Third-party contractor"])
    }

    // MARK: the sheet

    @Test func theSheetSaysSoWhenTheSystemFacesNobody() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        let sheet = ThreatActorsSheet(session: model, dismiss: {})

        #expect(
            sheet.says == "This system faces no threat actor. "
                + "Every threat keeps the catalogue's own likelihood."
        )

        model.setFacedThreatActors(["commodity-crimeware"])
        #expect(ThreatActorsSheet(session: model, dismiss: {}).says.contains("faces 1 of"))
    }

    @Test func theSheetDraws() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        let renderer = ImageRenderer(
            content: ThreatActorsSheet(session: model, dismiss: {})
                .frame(width: 900, height: 700)
        )
        renderer.scale = 1

        #expect(renderer.cgImage != nil)
    }
}
