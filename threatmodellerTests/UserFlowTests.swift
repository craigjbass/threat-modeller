import ArchitectureDSL
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// A user in the window, end to end: what the palette's User row puts on the
/// canvas, what the save writes into the `.arch` file, what the canvas draws,
/// and what the user panel writes.
@MainActor
@Suite("A user in the window")
struct UserFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    /// One user, no other component. `Uses` and `Reaches` have nothing to
    /// offer yet.
    private let onlyAUser = """
    system "Payments" {
      user "alice" {
        name = "Alice"
        role = "Operator"
      }
    }

    """

    private let phisher = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      adversary "phisher" {
        name    = "Phisher"
        role    = "Customer"
        reaches = ["api"]
      }
    }

    """

    private let insider = """
    system "Payments" {
      threat_actor "insider" {
        name       = "Disgruntled operator"
        capability = "targeted"
        intent     = "sabotage"
        performs   = ["credential-theft"]
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      user "alice" {
        name         = "Alice"
        role         = "Operator"
        access       = "admin"
        reaches      = ["api"]
        threat_actor = "insider"
      }
    }

    """

    /// Alice holds a browser and a mobile app. The browser reaches the api
    /// and the console; the mobile app reaches the api. The design in
    /// `docs/superpowers/specs/2026-09-18-user-through-a-client-design.md`
    /// states what the canvas draws for it.
    private let clients = """
    system "Payments" {
      technology "web" {
        name     = "Web Browser"
        category = "client"
      }

      technology "app" {
        name     = "Mobile App"
        category = "client"
      }

      component "api" {
        technology = "aws-ec2"
        name       = "API"
        data       = "confidential"
      }

      component "console" {
        technology = "aws-ec2"
        name       = "Admin console"
        data       = "confidential"
      }

      component "browser" {
        technology = "web"
      }

      component "mobile" {
        technology = "app"
      }

      user "alice" {
        name = "Alice"
        role = "Operator"
        uses = ["browser", "mobile"]
      }

      flow browser -> api
      flow browser -> console
      flow mobile -> api
    }

    """

    /// Alice holds no client yet. Three clients wait to be picked: a
    /// browser, a mobile app and a terminal.
    private let threeClients = """
    system "Payments" {
      technology "web" {
        name     = "Web Browser"
        category = "client"
      }

      technology "app" {
        name     = "Mobile App"
        category = "client"
      }

      technology "term" {
        name     = "Terminal"
        category = "client"
      }

      component "api" {
        technology = "aws-ec2"
        name       = "API"
        data       = "confidential"
      }

      component "browser" {
        technology = "web"
      }

      component "mobile" {
        technology = "app"
      }

      component "terminal" {
        technology = "term"
      }

      user "alice" {
        name = "Alice"
        role = "Operator"
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

    private func user(of model: ThreatModelSession) throws -> ViewedComponent {
        try #require(model.canvas.components.first { $0.isUser })
    }

    // MARK: the palette

    /// The drop from the palette's User row: the same path a technology drop
    /// takes, carrying the row's own word.
    @Test func aUserDroppedFromThePaletteWritesAUserBlockAndNoComponentBlock() async throws {
        let (session, useCases) = await aProject("system \"Payments\" {\n}\n")
        let model = try #require(session.model)

        model.add(technologyId: ThreatModelSession.userDropId, x: 120, y: 80)
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        let drawn = try user(of: model)
        #expect(written.contains("user \"\(drawn.id)\" {"))
        #expect(written.contains("name = \"User\""))
        #expect(written.contains("component \"") == false)
    }

    @Test func aDoubleClickOnTheUserRowPutsAUserOnTheCanvas() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        model.addAtDefaultPoint(technologyId: ThreatModelSession.userDropId)

        let drawn = try user(of: model)
        #expect(drawn.name == "User")
        #expect(drawn.x == ThreatModelSession.defaultDropPoint.x + 32)
    }

    @Test func thePaletteKeepsTheUserRowUntilASearchNamesSomethingElse() {
        #expect(PaletteSearch.showsUser(for: ""))
        #expect(PaletteSearch.showsUser(for: "use"))
        #expect(PaletteSearch.showsUser(for: "person"))
        #expect(PaletteSearch.showsUser(for: "aws-ec2") == false)
    }

    // MARK: the canvas

    @Test func theCanvasDrawsAUserWithTheActorShape() async throws {
        let (session, _) = await aProject(insider)
        let model = try #require(session.model)

        let alice = try user(of: model)

        #expect(alice.id == "alice")
        #expect(alice.shapeId == "actor")
        #expect(alice.role == "Operator")
        #expect(alice.runsAsId == "admin")
        #expect(alice.threatActorId == "insider")
        #expect(HoverText.node(alice, zoneName: nil, risk: nil).hasPrefix(
            "User, Operator, the threat actor insider"
        ))
    }

    /// The insider is one element: faced as an actor in the threat list, and
    /// drawn as a user on the canvas.
    @Test func anInsiderIsFacedInTheListAndDrawnOnTheCanvas() async throws {
        let (session, _) = await aProject(insider)
        let model = try #require(session.model)

        let theft = try #require(model.threats.first { $0.threatId == "credential-theft" })
        #expect(theft.likelihoodId == "targeted")
        #expect(theft.performedByLabels == ["Disgruntled operator"])
        #expect(try user(of: model).isUser)
        #expect(model.threats.contains { $0.source.id == "component:alice" } == false)
    }

    // MARK: the panel

    /// Issue #179: `Uses` and `Reaches` show even while the system holds no
    /// component to pick, with the empty-state message in place of the
    /// control.
    @Test func theFieldsShowTheEmptyStateWhenNoComponentExists() async throws {
        let (session, _) = await aProject(onlyAUser)
        let model = try #require(session.model)
        let panel = UserPanel(session: model, user: try user(of: model))

        #expect(panel.reachable.isEmpty)
        #expect(panel.usesField.choices.isEmpty)
        #expect(panel.usesField.emptyMessage == IdTokenField.noComponentMessage)
        #expect(panel.reachesField.choices.isEmpty)
        #expect(panel.reachesField.emptyMessage == IdTokenField.noComponentMessage)
    }

    @Test func thePanelWritesTheRoleTheAccessAndTheActorIntoTheFile() async throws {
        let (session, useCases) = await aProject(insider)
        let model = try #require(session.model)
        model.setUserProperties(
            componentId: "alice",
            name: "Alice",
            role: "",
            accessId: "user",
            uses: [],
            reaches: [],
            threatActorId: nil,
            isAdversary: false
        )

        var panel = UserPanel(session: model, user: try user(of: model))
        panel.commitRole("Operator")
        panel = UserPanel(session: model, user: try user(of: model))
        panel.access.wrappedValue = "admin"
        panel = UserPanel(session: model, user: try user(of: model))
        panel.threatActor.wrappedValue = "insider"
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("role         = \"Operator\""))
        #expect(written.contains("access       = \"admin\""))
        #expect(written.contains("threat_actor = \"insider\""))
    }

    /// The Kind picker writes the block keyword: the file holds
    /// `adversary "alice"` after the pick, and `user "alice"` again after the
    /// pick goes back.
    @Test func thePanelWritesTheAdversaryKeywordIntoTheFile() async throws {
        let (session, useCases) = await aProject(insider)
        let model = try #require(session.model)

        var panel = UserPanel(session: model, user: try user(of: model))
        #expect(panel.adversary.wrappedValue == false)
        panel.adversary.wrappedValue = true
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(try user(of: model).isAdversary)
        var written = try #require(architecture(useCases))
        #expect(written.contains("adversary \"alice\" {"))
        #expect(written.contains("user \"alice\" {") == false)
        #expect(written.contains("role         = \"Operator\""))
        #expect(written.contains("threat_actor = \"insider\""))

        panel = UserPanel(session: model, user: try user(of: model))
        #expect(panel.adversary.wrappedValue)
        panel.adversary.wrappedValue = false
        await session.save()

        written = try #require(architecture(useCases))
        #expect(written.contains("user \"alice\" {"))
        #expect(written.contains("adversary \"alice\" {") == false)
    }

    /// A file that states the `adversary` keyword draws an adversary on the
    /// canvas, with the actor shape a user takes.
    @Test func theCanvasDrawsAnAdversaryWithTheActorShape() async throws {
        let (session, _) = await aProject(phisher)
        let model = try #require(session.model)

        let drawn = try user(of: model)

        #expect(drawn.id == "phisher")
        #expect(drawn.isUser)
        #expect(drawn.isAdversary)
        #expect(drawn.shapeId == "actor")
    }

    @Test func thePanelStatesWhatTheUserReaches() async throws {
        let (session, _) = await aProject(insider)
        let model = try #require(session.model)

        let panel = UserPanel(session: model, user: try user(of: model))

        #expect(try user(of: model).reaches == ["api"])
        #expect(panel.reachableChoices.first { $0.id == "api" }?.name == "EC2")
        #expect(panel.reachable.map(\.id) == ["api"])
        #expect(panel.actorChoices.map(\.id).contains("insider"))
        #expect(panel.threatActor.wrappedValue == "insider")
    }

    // MARK: a user through a client

    /// One user, two clients, three targets: every node is drawn once, the
    /// links run user to client and client to target, and no link runs
    /// user to target.
    @Test func theCanvasDrawsTheUserItsClientsAndTheFlowsOnwardOnce() async throws {
        let (session, _) = await aProject(clients)
        let model = try #require(session.model)

        let drawn = model.canvas
        #expect(drawn.components.map(\.id).sorted() == ["alice", "api", "browser", "console", "mobile"])
        #expect(drawn.components.filter { $0.id == "alice" }.count == 1)
        #expect(drawn.components.filter { $0.id == "browser" }.count == 1)
        #expect(drawn.components.filter { $0.id == "mobile" }.count == 1)

        let links = drawn.connections.map { "\($0.sourceComponentId)->\($0.targetComponentId)" }
        #expect(links.sorted() == [
            "alice->browser", "alice->mobile", "browser->api", "browser->console", "mobile->api"
        ])
        #expect(links.contains("alice->api") == false)
        #expect(links.contains("alice->console") == false)
        let uses = drawn.connections.filter(\.isUse)
        #expect(uses.map(\.id) == ["use:alice:browser", "use:alice:mobile"])
        #expect(model.threats.contains { $0.source.id.hasPrefix("connection:use:") } == false)
    }

    /// A use link is drawn and not selected: a click on it hits nothing, so
    /// the flow panel never opens on it and the delete key never asks the
    /// model to remove it.
    @Test func aUseLinkIsDrawnAndNotSelected() async throws {
        let (session, _) = await aProject(clients)
        let model = try #require(session.model)
        let canvas = CanvasState()
        let gestures = CanvasGestures(session: model, canvas: canvas)

        let geometry = gestures.flows
        #expect(geometry.curves["use:alice:browser"] != nil)
        #expect(geometry.curves["browser->api"] != nil)
        let curve = try #require(geometry.curves["use:alice:browser"])
        let middle = curve.point(at: 0.5)
        let hit = geometry.connection(under: CGPoint(x: middle.x, y: middle.y), within: 1)
        #expect(hit != "use:alice:browser")
        #expect(geometry.callouts.contains { $0.connectionId == "use:alice:browser" } == false)
    }

    @Test func theHoverNamesTheClientsAUserHolds() async throws {
        let (session, _) = await aProject(clients)
        let model = try #require(session.model)

        let alice = try user(of: model)

        let said = HoverText.node(
            alice, zoneName: nil, risk: nil, clientNames: model.clientNames(of: alice.id)
        )
        #expect(said.hasPrefix("User, Operator, through Web Browser and Mobile App"))
    }

    @Test func thePanelWritesTheClientsIntoTheFile() async throws {
        let (session, useCases) = await aProject(clients)
        let model = try #require(session.model)

        var panel = UserPanel(session: model, user: try user(of: model))
        #expect(try user(of: model).uses == ["browser", "mobile"])

        // A token removed takes the id off the list and the file follows.
        panel.usesField.remove("browser")
        panel = UserPanel(session: model, user: try user(of: model))
        #expect(try user(of: model).uses == ["mobile"])
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("uses = [\"mobile\"]"))
        #expect(written.contains("flow alice") == false)
        #expect(model.canvas.connections.filter(\.isUse).map(\.id) == ["use:alice:mobile"])
    }

    /// A client alice's `uses` names leaves the model, by a path other than
    /// the panel. The file still names it in `uses`, and an unrelated edit
    /// on another component writes the file back with that name unchanged.
    @Test func aClientTheModelNoLongerHoldsRoundTripsAfterAnUnrelatedEdit() async throws {
        let (session, useCases) = await aProject(clients)
        let model = try #require(session.model)
        #expect(try user(of: model).uses == ["browser", "mobile"])

        useCases.modelStore.mutate(label: "test setup") { threatModel in
            threatModel.components.removeAll { $0.id.value == "browser" }
        }
        model.reread()

        #expect(try user(of: model).uses == ["browser", "mobile"])
        let api = try #require(model.canvas.components.first { $0.id == "api" })
        let panel = ComponentPanel(session: model, component: api)
        panel.commitTags("payments")
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("uses = [\"mobile\", \"browser\"]"))
        #expect(written.contains("tags"))
    }

    /// The acceptance criterion: three clients picked in one open of the
    /// list write in the order picked. `IdTokenFieldTests
    /// .picksThreeInOneOpenWithoutClosing` proves the list itself never
    /// closes between picks; this test proves the file that comes out of
    /// three such picks.
    @Test func picksThreeClientsInOneOpenOfTheListAndWritesThemInOrder() async throws {
        let (session, useCases) = await aProject(threeClients)
        let model = try #require(session.model)

        var panel = UserPanel(session: model, user: try user(of: model))
        for componentId in ["browser", "mobile", "terminal"] {
            let choice = try #require(panel.usesField.rows.first { $0.id == componentId })
            panel.usesField.pick(choice)
            panel = UserPanel(session: model, user: try user(of: model))
        }

        #expect(try user(of: model).uses == ["browser", "mobile", "terminal"])
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("uses = [\"browser\", \"mobile\", \"terminal\"]"))
    }

    /// The palette gesture: a technology dropped on a user is added beside
    /// the user and held by the user, with no form.
    @Test func aTechnologyDroppedOnAUserIsAddedBesideItAndHeld() async throws {
        let (session, useCases) = await aProject(insider)
        let model = try #require(session.model)
        let canvas = CanvasState()
        let gestures = CanvasGestures(session: model, canvas: canvas)
        let alice = try user(of: model)
        let centre = CGPoint(
            x: alice.x + Component.size.width / 2,
            y: alice.y + Component.size.height / 2
        )

        #expect(gestures.drop(["aws-ec2"], at: canvas.transform.viewPoint(centre)))
        await session.save()

        let added = try #require(model.canvas.components.first { $0.isUser == false && $0.id != "api" })
        #expect(added.x == alice.x + Component.size.width + ThreatModelSession.clientGap)
        #expect(added.y == alice.y)
        #expect(try user(of: model).uses == [added.id])
        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("uses         = [\"\(added.id)\"]"))
    }

    /// The second gesture: a flow dragged from a user to a client writes
    /// `uses` and no flow. A flow dragged from a user to any other
    /// component writes a flow, as it did.
    @Test func aFlowDraggedFromAUserToAClientWritesUsesAndNoFlow() async throws {
        let (session, useCases) = await aProject(clients)
        let model = try #require(session.model)
        UserPanel(session: model, user: try user(of: model)).usesField.remove("browser")
        #expect(try user(of: model).uses == ["mobile"])

        model.connect(sourceComponentId: "alice", targetComponentId: "browser")
        model.connect(sourceComponentId: "alice", targetComponentId: "api")
        await session.save()

        #expect(try user(of: model).uses == ["mobile", "browser"])
        let flows = model.canvas.connections.filter { $0.isUse == false }
            .map { "\($0.sourceComponentId)->\($0.targetComponentId)" }
        #expect(flows.contains("alice->browser") == false)
        #expect(flows.contains("alice->api"))
        #expect(model.canvas.connections.filter(\.isUse).map(\.id) == ["use:alice:mobile", "use:alice:browser"])
        let written = try #require(architecture(useCases))
        #expect(written.contains("uses = [\"browser\", \"mobile\"]"))
        #expect(written.contains("flow alice -> api"))
        #expect(written.contains("flow alice -> browser") == false)
    }

    @Test func thePanelRefusesNothingTheParserTakes() async throws {
        let (session, useCases) = await aProject(insider)
        let model = try #require(session.model)

        UserPanel(session: model, user: try user(of: model)).threatActor.wrappedValue = ""
        await session.save()

        #expect(model.errorMessage == nil)
        #expect(architecture(useCases)?.contains("threat_actor = \"insider\"") == false)
        let theft = try #require(model.threats.first { $0.threatId == "credential-theft" })
        #expect(theft.likelihoodId == "commodity")
    }
}
