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

        #expect(app.removeAssumption().execute(RemoveAssumptionRequest(label: "network-segmented")) == .removed)
        #expect(assumptions.isEmpty)
    }

    @Test func saysSoWhenNothingHoldsThatLabel() {
        #expect(app.removeAssumption().execute(RemoveAssumptionRequest(label: "nothing")) == .noSuchAssumption)
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
