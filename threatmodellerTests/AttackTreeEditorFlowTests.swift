import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Writing a tree in the window, end to end: the draft the sheet holds, the
/// file the use case writes, the score the model gives it, and the report.
@MainActor
@Suite("Writing an attack tree in the window")
struct AttackTreeEditorFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "db" {
        technology = "aws-rds"
        data       = "restricted"
      }

      flow api -> db
    }

    """

    private func aProject() async -> (ProjectSession, TestDependencies) {
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

    // MARK: the draft

    /// A step names a threat by the key the assessment hands out, so a tree
    /// the window writes binds to the model.
    @Test func aDraftStatesTheTreeTheFileWillHold() throws {
        let draft = TreeDraft(
            id: "read-every-record",
            name: "Read every record",
            description: "How a caller reaches the table.",
            raisesRiskBy: 40,
            goalKey: "misconfiguration@component:db",
            steps: [TreeDraft.Step(key: "credential-theft@component:api", note: "IMDS")]
        )

        let tree = try #require(draft.source())
        #expect(tree.id == "read-every-record")
        #expect(tree.raisesRiskBy == 40)
        #expect(tree.goal.threatId == "misconfiguration")
        #expect(tree.goal.sourceKind == "component")
        #expect(tree.goal.sourceId == "db")
        #expect(tree.steps.map(\.target.threatId) == ["credential-theft"])
        #expect(tree.steps.first?.note == "IMDS")
    }

    /// A flow is a `flow` in the language and a `connection` in the
    /// assessment's own keys, and one rule reads both.
    @Test func aDraftReadsAFlowsOwnKey() throws {
        let draft = TreeDraft(
            id: "one",
            name: "One",
            description: "",
            raisesRiskBy: 0,
            goalKey: "connection-mitm@connection:api->db",
            steps: [TreeDraft.Step(key: "connection-mitm@connection:api->db", note: nil)]
        )

        let tree = try #require(draft.source())
        #expect(tree.goal.sourceKind == "flow")
        #expect(tree.goal.sourceId == "api->db")
        #expect(TreeDraft.key(of: tree.goal) == "connection-mitm@connection:api->db")
    }

    /// A tree body holds exactly one root, and a root of nothing is not a
    /// tree.
    @Test func aDraftWithNoStepStatesNoTree() {
        let draft = TreeDraft(
            id: "one",
            name: "One",
            description: "",
            raisesRiskBy: 0,
            goalKey: "misconfiguration@component:db",
            steps: []
        )

        #expect(draft.source() == nil)
    }

    // MARK: the window

    @Test func writesTheTreeAndTheModelScoresIt() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let goal = try #require(
            model.threats.first { $0.threatId == "misconfiguration" && $0.source.id == "component:db" }
        )
        let step = try #require(
            model.threats.first { $0.threatId == "credential-theft" }
        )

        let draft = TreeDraft(
            id: "read-every-record",
            name: "Read every record",
            description: "How a caller reaches the table.",
            raisesRiskBy: 40,
            goalKey: goal.threatKey,
            steps: [TreeDraft.Step(key: step.threatKey, note: nil)]
        )
        await session.writeAttackTree(try #require(draft.source()))

        let written = try #require(
            useCases.project.text(at: "/work/threatmodel/payments.attacktree")
        )
        #expect(written.contains("attack_trees for \"Payments\" {"))
        #expect(written.contains("tree \"read-every-record\" {"))
        #expect(written.contains("raises_risk_by = 40"))

        // The project read the files again, so the model holds the tree.
        let reloaded = try #require(session.model)
        let bound = try #require(reloaded.attackTrees.first)
        #expect(bound.id == "read-every-record")
        #expect(bound.isStale == false)
        #expect(session.errorMessage == nil)
    }

    @Test func theReportStatesTheTreeTheWindowWrote() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let goal = try #require(
            model.threats.first { $0.threatId == "misconfiguration" && $0.source.id == "component:db" }
        )

        let draft = TreeDraft(
            id: "read-every-record",
            name: "Read every record",
            description: "",
            raisesRiskBy: 40,
            goalKey: goal.threatKey,
            steps: [TreeDraft.Step(key: goal.threatKey, note: nil)]
        )
        await session.writeAttackTree(try #require(draft.source()))

        let reloaded = try #require(session.model)
        let markdown = reloaded.markdownExport()

        #expect(String(decoding: markdown.data, as: UTF8.self).contains("Read every record"))
    }

    @Test func deletesTheTreeAndTheFileStatesNone() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let goal = try #require(model.threats.first)
        let draft = TreeDraft(
            id: "one",
            name: "One",
            description: "",
            raisesRiskBy: 0,
            goalKey: goal.threatKey,
            steps: [TreeDraft.Step(key: goal.threatKey, note: nil)]
        )
        await session.writeAttackTree(try #require(draft.source()))

        await session.removeAttackTree("one")

        let written = try #require(
            useCases.project.text(at: "/work/threatmodel/payments.attacktree")
        )
        #expect(written.contains("tree \"one\"") == false)
        #expect(session.attackTreeSources.isEmpty)
    }

    @Test func theSheetListsWhatTheFileStates() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let goal = try #require(model.threats.first)
        let draft = TreeDraft(
            id: "one",
            name: "One",
            description: "",
            raisesRiskBy: 0,
            goalKey: goal.threatKey,
            steps: [TreeDraft.Step(key: goal.threatKey, note: nil)]
        )
        await session.writeAttackTree(try #require(draft.source()))

        #expect(session.attackTreeSources.map(\.id) == ["one"])
    }
}
