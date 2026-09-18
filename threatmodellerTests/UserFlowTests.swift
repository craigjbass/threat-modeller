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
            threatActorId: nil
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

    @Test func thePanelStatesWhatTheUserReaches() async throws {
        let (session, _) = await aProject(insider)
        let model = try #require(session.model)

        let panel = UserPanel(session: model, user: try user(of: model))

        #expect(panel.reachesLabel == "Reaches EC2")
        #expect(panel.reachable.map(\.id) == ["api"])
        #expect(panel.actorChoices.map(\.id).contains("insider"))
        #expect(panel.threatActor.wrappedValue == "insider")
    }

    // MARK: a user through a client

    @Test func thePanelWritesTheClientsIntoTheFile() async throws {
        let (session, useCases) = await aProject(clients)
        let model = try #require(session.model)

        var panel = UserPanel(session: model, user: try user(of: model))
        #expect(panel.usesLabel == "Uses 2 components")
        #expect(panel.uses("browser").wrappedValue)
        panel.uses("browser").wrappedValue = false
        panel = UserPanel(session: model, user: try user(of: model))
        #expect(panel.usesLabel == "Uses Mobile App")
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("uses = [\"mobile\"]"))
        #expect(written.contains("flow alice") == false)
        #expect(model.canvas.connections.filter(\.isUse).map(\.id) == ["use:alice:mobile"])
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
