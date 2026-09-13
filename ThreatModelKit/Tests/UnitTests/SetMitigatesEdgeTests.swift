import Testing
import ThreatModelKit
import TestSupport

@Suite("Saying that one component lowers a threat on another")
struct SetMitigatesEdgeTests {
    private let app = TestDependencies()

    private func aModelOfTwoComponents() -> (guardId: String, storeId: String) {
        guard case .added(let guardId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "internal")
        ), case .added(let storeId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 400, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the two components were not added")
            return ("", "")
        }
        return (guardId, storeId)
    }

    private func set(
        from source: String,
        to target: String,
        threats: [String] = ["credential-theft"],
        reducesRiskBy: Int = 80,
        status: String = "assumed",
        action: SetMitigatesEdgeRequest.Action? = nil
    ) -> SetMitigatesEdgeResponse {
        app.setMitigatesEdge().execute(
            SetMitigatesEdgeRequest(
                sourceComponentId: source,
                targetComponentId: target,
                threatIds: threats,
                reducesRiskBy: reducesRiskBy,
                status: status,
                action: action
            )
        )
    }

    private var edges: [MitigatesEdge] { app.modelStore.current().mitigatesEdges }

    @Test func writesOneDown() {
        let (guardId, storeId) = aModelOfTwoComponents()

        #expect(set(from: guardId, to: storeId) == .recorded)

        #expect(edges.count == 1)
        #expect(edges.first?.source.value == guardId)
        #expect(edges.first?.target.value == storeId)
        #expect(edges.first?.threatIds.map(\.value) == ["credential-theft"])
        #expect(edges.first?.reducesRiskBy == 80)
        #expect(edges.first?.status == .assumed)
    }

    /// The two ends name the edge, the way they name a flow.
    @Test func changesTheEdgeBetweenTheSameTwoEnds() {
        let (guardId, storeId) = aModelOfTwoComponents()
        _ = set(from: guardId, to: storeId, reducesRiskBy: 40)

        #expect(set(from: guardId, to: storeId, reducesRiskBy: 90) == .recorded)

        #expect(edges.count == 1)
        #expect(edges.first?.reducesRiskBy == 90)
    }

    @Test func refusesAnEdgeThatNamesNoThreats() {
        let (guardId, storeId) = aModelOfTwoComponents()

        #expect(set(from: guardId, to: storeId, threats: []) == .noThreats)
        #expect(edges.isEmpty)
    }

    @Test func refusesAReductionOutsideItsRange() {
        let (guardId, storeId) = aModelOfTwoComponents()

        #expect(set(from: guardId, to: storeId, reducesRiskBy: 101) == .reductionOutOfRange)
        #expect(set(from: guardId, to: storeId, reducesRiskBy: -1) == .reductionOutOfRange)
        #expect(edges.isEmpty)
    }

    @Test func refusesAStatusTheLanguageDoesNotRead() {
        let (guardId, storeId) = aModelOfTwoComponents()

        #expect(set(from: guardId, to: storeId, status: "planned") == .unknownStatus)
        #expect(edges.isEmpty)
    }

    @Test func refusesAnEndTheModelNoLongerHolds() {
        let (guardId, _) = aModelOfTwoComponents()

        #expect(set(from: guardId, to: "gone") == .unknownComponent)
        #expect(set(from: "gone", to: guardId) == .unknownComponent)
    }

    /// A component cannot lower a threat on itself.
    @Test func refusesAnEdgeFromAComponentToItself() {
        let (guardId, _) = aModelOfTwoComponents()

        #expect(set(from: guardId, to: guardId) == .selfEdge)
        #expect(edges.isEmpty)
    }

    // MARK: what a team would do to adopt it

    @Test func carriesTheActionOnAnAssumedEdge() {
        let (guardId, storeId) = aModelOfTwoComponents()

        _ = set(
            from: guardId,
            to: storeId,
            status: "assumed",
            action: .init(label: "adopt-the-guard", text: "Adopt the guard", note: nil, blockedBy: nil, sources: [])
        )

        #expect(edges.first?.action?.label == "adopt-the-guard")
        #expect(edges.first?.action?.text == "Adopt the guard")
    }

    /// Language guide 4.7: only an assumed edge carries a recommendation. An
    /// adopted one has no leverage left to claim.
    @Test func dropsTheActionOnAnAdoptedEdge() {
        let (guardId, storeId) = aModelOfTwoComponents()

        let response = set(
            from: guardId,
            to: storeId,
            status: "adopted",
            action: .init(label: "adopt-the-guard", text: "Adopt the guard", note: nil, blockedBy: nil, sources: [])
        )

        #expect(response == .recordedWithoutTheAction)
        #expect(edges.first?.status == .adopted)
        #expect(edges.first?.action == nil)
    }

    // MARK: taking one off

    @Test func removesAnEdge() {
        let (guardId, storeId) = aModelOfTwoComponents()
        _ = set(from: guardId, to: storeId)

        let response = app.removeMitigatesEdge().execute(
            RemoveMitigatesEdgeRequest(sourceComponentId: guardId, targetComponentId: storeId)
        )

        #expect(response == .removed)
        #expect(edges.isEmpty)
    }

    @Test func saysSoWhenNoEdgeRunsBetweenThoseEnds() {
        let (guardId, storeId) = aModelOfTwoComponents()

        let response = app.removeMitigatesEdge().execute(
            RemoveMitigatesEdgeRequest(sourceComponentId: guardId, targetComponentId: storeId)
        )

        #expect(response == .noSuchEdge)
    }

    /// The point of the use case: the edge has to come out in the file, and
    /// the language has to read back what it wrote.
    @Test func writesTheEdgeOutAndReadsItBack() throws {
        app.project.put(
            """
            system "Payments" {
              component "guard" { technology = "aws-waf" }
              component "store" { technology = "aws-rds" }
            }
            """,
            at: "/work/threatmodel/payments.arch"
        )
        _ = app.openProject().execute(OpenProjectRequest(root: "/work"))
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        #expect(set(from: "guard", to: "store", reducesRiskBy: 80, status: "assumed") == .recorded)
        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))

        let written = try #require(app.project.text(at: "/work/threatmodel/payments.arch"))
        #expect(written.contains("mitigates guard -> store"))
        #expect(written.contains("reduces_risk_by = 80"))
        #expect(written.contains("\"assumed\""))

        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        #expect(edges.count == 1)
        #expect(edges.first?.reducesRiskBy == 80)
        #expect(edges.first?.status == .assumed)
    }
}
