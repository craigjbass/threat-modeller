import Testing
import ThreatModelKit
import TestSupport

@Suite("Writing down what a system takes on trust")
struct SetAssumptionTests {
    private let app = TestDependencies()

    private func set(
        label: String,
        text: String = "The network is segmented.",
        owner: String? = "platform"
    ) -> SetAssumptionResponse {
        app.setAssumption().execute(
            SetAssumptionRequest(label: label, text: text, owner: owner)
        )
    }

    private var assumptions: [SystemAssumption] {
        app.modelStore.current().assumptions
    }

    private var edges: [MitigatesEdge] {
        app.modelStore.current().mitigatesEdges
    }

    @Test func writesOneDown() {
        #expect(set(label: "network-segmented") == .recorded)

        #expect(assumptions.count == 1)
        #expect(assumptions.first?.label == "network-segmented")
        #expect(assumptions.first?.text == "The network is segmented.")
        #expect(assumptions.first?.owner == "platform")
    }

    /// The label names the assumption, so writing the same label again changes
    /// the one that is there rather than adding a second.
    @Test func changesTheOneThatIsAlreadyThere() {
        _ = set(label: "network-segmented", text: "First.")

        #expect(set(label: "network-segmented", text: "Second.") == .recorded)

        #expect(assumptions.count == 1)
        #expect(assumptions.first?.text == "Second.")
    }

    @Test func keepsTheOrderTheyWereWrittenIn() {
        _ = set(label: "a")
        _ = set(label: "b")
        _ = set(label: "c")
        _ = set(label: "b", text: "Changed.")

        #expect(assumptions.map(\.label) == ["a", "b", "c"])
    }

    /// An assumption with no text says nothing, which the language refuses.
    @Test func refusesAnAssumptionThatSaysNothing() {
        #expect(set(label: "network-segmented", text: "   ") == .noText)
        #expect(assumptions.isEmpty)
    }

    @Test func refusesAnAssumptionWithNoLabel() {
        #expect(set(label: "  ") == .noLabel)
        #expect(assumptions.isEmpty)
    }

    /// An owner nobody named is no owner, not an empty one.
    @Test func takesNoOwnerRatherThanAnEmptyOne() {
        _ = set(label: "network-segmented", owner: "   ")

        #expect(assumptions.first?.owner == nil)
    }

    @Test func removesOneWhenTheTextIsCleared() {
        _ = set(label: "network-segmented")

        #expect(
            app.removeAssumption().execute(RemoveAssumptionRequest(label: "network-segmented"))
                == .removed(unblockedActions: 0)
        )
        #expect(assumptions.isEmpty)
    }

    @Test func saysSoWhenNothingHoldsThatLabel() {
        #expect(app.removeAssumption().execute(RemoveAssumptionRequest(label: "nothing")) == .noSuchAssumption)
    }

    @Test func namesTheRemovalForTheEditMenu() {
        _ = set(label: "network-segmented")

        _ = app.removeAssumption().execute(RemoveAssumptionRequest(label: "network-segmented"))

        #expect(app.modelStore.undoLabel == ChangeLabel.removeAssumption)
    }

    @Test func clearsTheBlockerOnEveryEdgeThatNamesTheRemovedAssumption() {
        guard case .added(let guardId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        ), case .added(let storeId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 400, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the two components were not added")
            return
        }
        _ = set(label: "guard-not-deployed", text: "The guard is bought and not deployed.")
        _ = app.setMitigatesEdge().execute(
            SetMitigatesEdgeRequest(
                sourceComponentId: guardId,
                targetComponentId: storeId,
                status: "proposed",
                action: SetMitigatesEdgeRequest.Action(
                    label: "adopt-the-guard",
                    text: "Adopt the guard",
                    blockedBy: "guard-not-deployed"
                )
            )
        )

        #expect(
            app.removeAssumption().execute(RemoveAssumptionRequest(label: "guard-not-deployed"))
                == .removed(unblockedActions: 1)
        )

        #expect(assumptions.isEmpty)
        #expect(edges.first?.action?.label == "adopt-the-guard")
        #expect(edges.first?.action?.blockedBy == nil)
    }

    private let anAssumedEdgeNamingTheRemovedAssumption = """
    system "Payments" {
      component "guard" {
        technology = "aws-ec2"
      }
      component "store" {
        technology = "aws-rds"
      }
      assumption "guard-not-deployed" {
        text = "The guard is bought and not deployed."
      }
      mitigates guard -> store {
        status          = "proposed"

        recommendation "adopt-the-guard" {
          text       = "Adopt the guard"
          blocked_by = "guard-not-deployed"
        }
      }
    }
    """

    @Test func keepsTheEdgesActionThroughSaveAndOpenWhenTheAssumptionIsRemoved() throws {
        app.project.put(anAssumedEdgeNamingTheRemovedAssumption, at: "/work/threatmodel/payments.arch")
        _ = app.openProject().execute(OpenProjectRequest(root: "/work"))
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        _ = app.removeAssumption().execute(RemoveAssumptionRequest(label: "guard-not-deployed"))
        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        let written = try #require(app.project.text(at: "/work/threatmodel/payments.arch"))
        #expect(written.contains("blocked_by") == false)
        #expect(written.contains("assumption \"guard-not-deployed\"") == false)
        #expect(edges.count == 1)
        #expect(edges.first?.action?.label == "adopt-the-guard")
        #expect(edges.first?.action?.text == "Adopt the guard")
        #expect(edges.first?.action?.blockedBy == nil)
    }

    /// The point of the use case is that the interface can reach the feature,
    /// which means the assumption has to come out in the file.
    @Test func writesTheAssumptionOutToTheArchitectureFile() throws {
        app.project.put(
            "system \"Payments\" { component \"api\" { technology = \"aws-ec2\" } }",
            at: "/work/threatmodel/payments.arch"
        )
        _ = app.openProject().execute(OpenProjectRequest(root: "/work"))
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        _ = set(label: "network-segmented")
        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))

        let written = try #require(app.project.text(at: "/work/threatmodel/payments.arch"))
        #expect(written.contains("assumption \"network-segmented\""))
        #expect(written.contains("The network is segmented."))
        #expect(written.contains("platform"))
    }

    /// And that the language reads back what it wrote.
    @Test func readsBackTheAssumptionItWrote() throws {
        app.project.put(
            "system \"Payments\" { component \"api\" { technology = \"aws-ec2\" } }",
            at: "/work/threatmodel/payments.arch"
        )
        _ = app.openProject().execute(OpenProjectRequest(root: "/work"))
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        _ = set(label: "network-segmented")
        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))

        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        #expect(assumptions.count == 1)
        #expect(assumptions.first?.label == "network-segmented")
        #expect(assumptions.first?.owner == "platform")
    }
}
