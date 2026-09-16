import ArchitectureDSL
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Picking a shape in the component panel, end to end: what the pick writes
/// into the `.arch` file of a flat system, what it writes into the part file
/// of a split system, and what a reopened project draws.
@MainActor
@Suite("A shape picked in the component panel")
struct ComponentShapeFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aFlatProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func aSplitProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(
            "system \"Payments\" { }",
            at: "/work/threatmodel/payments/arch/payments.arch"
        )
        useCases.project.put(
            "component \"api\" { technology = \"aws-ec2\" }",
            at: "/work/threatmodel/payments/arch/edge.arch"
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func panel(
        _ model: ThreatModelSession,
        componentId: String
    ) throws -> ComponentPanel {
        let component = try #require(model.canvas.components.first { $0.id == componentId })
        return ComponentPanel(session: model, component: component)
    }

    /// One line of the file, with the spaces that line the equals signs up
    /// taken out.
    private func attributes(_ text: String?) -> [String] {
        (text ?? "").split(separator: "\n").map { String($0.filter { $0 != " " }) }
    }

    // MARK: a flat system

    @Test func thePickWritesTheShapeIntoTheArchitectureFile() async throws {
        let (session, useCases) = await aFlatProject()
        let model = try #require(session.model)

        try panel(model, componentId: "api").shape.wrappedValue = "store"
        await session.save()

        #expect(model.errorMessage == nil)
        let file = useCases.project.text(at: "/work/threatmodel/payments.arch")
        #expect(attributes(file).contains("shape=\"store\""))
    }

    /// Auto takes the line back off, so the file states only what a person
    /// chose.
    @Test func pickingAutoTakesTheShapeLineBackOff() async throws {
        let (session, useCases) = await aFlatProject()
        let model = try #require(session.model)
        try panel(model, componentId: "api").shape.wrappedValue = "store"
        await session.save()

        try panel(model, componentId: "api").shape.wrappedValue = ""
        await session.save()

        let file = useCases.project.text(at: "/work/threatmodel/payments.arch")
        #expect(attributes(file).contains { $0.hasPrefix("shape=") } == false)
    }

    // MARK: a split system

    @Test func thePickWritesTheShapeIntoThePartFileThatHoldsTheComponent() async throws {
        let (session, useCases) = await aSplitProject()
        let model = try #require(session.model)

        try panel(model, componentId: "api").shape.wrappedValue = "actor"
        await session.save()

        #expect(model.errorMessage == nil)
        let part = useCases.project.text(at: "/work/threatmodel/payments/arch/edge.arch")
        #expect(attributes(part).contains("shape=\"actor\""))
    }

    // MARK: reading it back

    @Test func aReopenedProjectDrawsThePickedShape() async throws {
        let (session, useCases) = await aFlatProject()
        let model = try #require(session.model)
        try panel(model, componentId: "api").shape.wrappedValue = "store"
        await session.save()

        let reopened = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await reopened.open(root: "/work")

        let drawn = try #require(reopened.model?.canvas.components.first { $0.id == "api" })
        #expect(drawn.shapeId == "store")
        #expect(drawn.shapeOverrideId == "store")
    }
}
