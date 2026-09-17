import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// The `asset` block a component states on itself.
///
/// Language guide section 4.5. The block names one thing of value the
/// component holds, and states the classification of that thing. A component
/// scores at the highest sensitivity among its own `data` word and every
/// asset it states.
@Suite("The assets a component states on itself")
struct ComponentAssetTests {
    private let app = TestDependencies()

    private let plain = """
    system "Payments" {
      component "workstation" {
        technology = "aws-ec2"
        data       = "internal"
      }
    }

    """

    private let withAsset = """
    system "Payments" {
      component "workstation" {
        technology = "aws-ec2"
        data       = "internal"

        asset "ssh-keys" {
          data = "restricted"
        }
      }
    }

    """

    private func drawTheModel(_ text: String) {
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: text))
    }

    private func viewed(_ componentId: String) -> ViewedComponent? {
        app.viewThreatModel().execute(ViewThreatModelRequest())
            .components.first { $0.id == componentId }
    }

    // MARK: writing the block

    @Test func aPersonWritesAnAssetOnAComponent() {
        drawTheModel(plain)

        #expect(
            app.setComponentAsset().execute(
                SetComponentAssetRequest(
                    componentId: "workstation",
                    name: "ssh-keys",
                    classification: "restricted"
                )
            ) == .recorded
        )

        #expect(viewed("workstation")?.assets.map(\.name) == ["ssh-keys"])
        #expect(viewed("workstation")?.assets.map(\.classificationId) == ["restricted"])
    }

    @Test func writingTheSameNameAgainChangesTheOneThatIsThere() {
        drawTheModel(withAsset)

        _ = app.setComponentAsset().execute(
            SetComponentAssetRequest(
                componentId: "workstation",
                name: "ssh-keys",
                classification: "confidential"
            )
        )

        #expect(viewed("workstation")?.assets.count == 1)
        #expect(viewed("workstation")?.assets.first?.classificationId == "confidential")
    }

    @Test func anAssetNeedsANameAKnownWordAndAComponentThatIsThere() {
        drawTheModel(plain)

        #expect(
            app.setComponentAsset().execute(
                SetComponentAssetRequest(
                    componentId: "workstation",
                    name: " ",
                    classification: "restricted"
                )
            ) == .noName
        )
        #expect(
            app.setComponentAsset().execute(
                SetComponentAssetRequest(
                    componentId: "workstation",
                    name: "ssh-keys",
                    classification: "money"
                )
            ) == .unknownClassification
        )
        #expect(
            app.setComponentAsset().execute(
                SetComponentAssetRequest(
                    componentId: "nothing",
                    name: "ssh-keys",
                    classification: "restricted"
                )
            ) == .unknownComponent
        )
    }

    // MARK: taking the block off

    @Test func aPersonTakesAnAssetOffAComponent() {
        drawTheModel(withAsset)

        #expect(
            app.removeComponentAsset().execute(
                RemoveComponentAssetRequest(componentId: "workstation", name: "ssh-keys")
            ) == .removed
        )
        #expect(viewed("workstation")?.assets.isEmpty == true)

        #expect(
            app.removeComponentAsset().execute(
                RemoveComponentAssetRequest(componentId: "workstation", name: "ssh-keys")
            ) == .noSuchAsset
        )
        #expect(
            app.removeComponentAsset().execute(
                RemoveComponentAssetRequest(componentId: "nothing", name: "ssh-keys")
            ) == .unknownComponent
        )
    }

    // MARK: the score

    /// A component scores at the highest sensitivity among its own word and
    /// every asset it states. The asset never lowers what the component
    /// states.
    @Test func aComponentScoresAtTheHighestAssetItStates() {
        drawTheModel(plain)
        let before = app.assessThreatModel().execute(AssessThreatModelRequest()).threats

        _ = app.setComponentAsset().execute(
            SetComponentAssetRequest(
                componentId: "workstation",
                name: "ssh-keys",
                classification: "restricted"
            )
        )
        let after = app.assessThreatModel().execute(AssessThreatModelRequest()).threats

        #expect(after.isEmpty == false)
        #expect(after.map(\.riskScore) != before.map(\.riskScore))
    }

    // MARK: the round trip

    /// The one writer writes the block the parser reads, and a read of that
    /// text gives the same model back.
    @Test func theBlockTheUseCaseWritesReadsBackAsTheSameModel() {
        drawTheModel(plain)

        _ = app.setComponentAsset().execute(
            SetComponentAssetRequest(
                componentId: "workstation",
                name: "ssh-keys",
                classification: "restricted"
            )
        )
        let written = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(written == withAsset)

        let fresh = TestDependencies()
        _ = fresh.importArchitecture().execute(ImportArchitectureRequest(text: written))
        let again = fresh.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(again == withAsset)
    }

    @Test func takingTheAssetOffWritesTheFileBackWithNoBlock() {
        drawTheModel(withAsset)

        _ = app.removeComponentAsset().execute(
            RemoveComponentAssetRequest(componentId: "workstation", name: "ssh-keys")
        )

        #expect(app.exportArchitecture().execute(ExportArchitectureRequest()).text == plain)
    }
}
