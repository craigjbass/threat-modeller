import Testing
import ThreatModelKit
@testable import threatmodeller

/// Narrowing the canvas to one tag view.
@Suite("Narrowing the canvas to one tag")
struct TagFilterTests {
    private func component(_ id: String, tags: [String]) -> ViewedComponent {
        ViewedComponent(
            id: id,
            technologyId: "aws-ec2",
            name: id,
            customName: nil,
            providerId: "aws",
            categoryId: "compute",
            x: 0,
            y: 0,
            sensitivityId: "internal",
            threatsDisabled: false,
            isUnknownTechnology: false,
            zoneId: nil,
            tags: tags
        )
    }

    private func zone(_ id: String, tags: [String]) -> ViewedZone {
        ViewedZone(
            id: id,
            name: id,
            customName: nil,
            networkZoneId: "private",
            networkTypeId: "generic",
            riskReductionEnabled: true,
            riskReductionPercent: 20,
            x: 0,
            y: 0,
            width: 100,
            height: 100,
            tags: tags
        )
    }

    private func flow(_ source: String, _ target: String, tags: [String] = []) -> ViewedConnection {
        ViewedConnection(
            id: "\(source)->\(target)",
            sourceComponentId: source,
            targetComponentId: target,
            tags: tags
        )
    }

    /// A model of three views: payments, data protection and operations.
    private var model: ViewThreatModelResponse {
        ViewThreatModelResponse(
            name: "Payments",
            components: [
                component("api", tags: ["payments", "pci"]),
                component("ledger", tags: ["payments"]),
                component("logs", tags: ["operations"]),
                component("plain", tags: [])
            ],
            connections: [
                flow("api", "ledger", tags: ["payments"]),
                flow("api", "logs"),
                flow("ledger", "plain")
            ],
            zones: [
                zone("app", tags: ["payments"]),
                zone("shared", tags: [])
            ]
        )
    }

    // MARK: what the toolbar offers

    @Test func listsEveryTagTheSystemStates() {
        #expect(TagFilter.tags(in: model) == ["operations", "payments", "pci"])
    }

    @Test func listsNoTagForAModelThatStatesNone() {
        let plain = ViewThreatModelResponse(
            name: "Payments",
            components: [component("api", tags: [])],
            connections: [],
            zones: []
        )

        #expect(TagFilter.tags(in: plain).isEmpty)
    }

    // MARK: what the canvas draws

    @Test func drawsTheWholeModelWhileNoTagIsPicked() {
        let filter = TagFilter()
        let drawn = filter.narrow(model)

        #expect(filter.isNarrowing == false)
        #expect(drawn.components.map(\.id) == ["api", "ledger", "logs", "plain"])
        #expect(drawn.zones.map(\.id) == ["app", "shared"])
        #expect(drawn.connections.count == 3)
    }

    @Test func drawsOnlyTheElementsThatHoldOneOfTwoPickedTags() {
        var filter = TagFilter()
        filter.pick("payments")
        filter.pick("operations")

        let drawn = filter.narrow(model)

        #expect(filter.isNarrowing)
        #expect(drawn.components.map(\.id) == ["api", "ledger", "logs"])
        #expect(drawn.zones.map(\.id) == ["app"])
    }

    @Test func drawsOnlyTheFlowsBetweenTheElementsItDraws() {
        var filter = TagFilter()
        filter.pick("payments")

        let drawn = filter.narrow(model)

        #expect(drawn.components.map(\.id) == ["api", "ledger"])
        // `ledger -> plain` leaves the view, so the canvas draws neither end
        // of it, and `api -> logs` ends on a component nothing draws.
        #expect(drawn.connections.map(\.id) == ["api->ledger"])
    }

    @Test func pickingATagTwiceDropsIt() {
        var filter = TagFilter()
        filter.pick("payments")
        filter.pick("payments")

        #expect(filter.isNarrowing == false)
        #expect(filter.isPicked("payments") == false)
    }

    @Test func clearFilterDrawsTheWholeModelAgain() {
        var filter = TagFilter()
        filter.pick("payments")
        filter.clear()

        let drawn = filter.narrow(model)

        #expect(filter.isNarrowing == false)
        #expect(drawn.components.count == 4)
        #expect(drawn.zones.count == 2)
        #expect(drawn.connections.count == 3)
    }

    @Test func aTagNoElementHoldsDrawsNothing() {
        var filter = TagFilter()
        filter.pick("finance")

        let drawn = filter.narrow(model)

        #expect(drawn.components.isEmpty)
        #expect(drawn.zones.isEmpty)
        #expect(drawn.connections.isEmpty)
    }

    // MARK: the words a person types

    @Test func readsACommaSeparatedLineAsTags() {
        #expect(TagFilter.tags(from: " payments , pci ") == ["payments", "pci"])
        #expect(TagFilter.tags(from: "payments,,payments") == ["payments"])
        #expect(TagFilter.tags(from: "   ").isEmpty)
    }

    @Test func writesTagsBackAsACommaSeparatedLine() {
        #expect(TagFilter.text(from: ["payments", "pci"]) == "payments, pci")
        #expect(TagFilter.text(from: []) == "")
    }
}
