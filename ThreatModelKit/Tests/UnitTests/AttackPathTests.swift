import Testing
import ThreatModelKit
import TestSupport

struct AttackPathTests {
    private func component(
        _ id: String,
        _ sensitivity: DataSensitivity = .internalData
    ) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: sensitivity
        )
    }

    private func flow(_ source: String, _ target: String, _ kind: FlowKind = .network) -> Connection {
        Connection(
            id: ConnectionId("\(source)->\(target)"),
            source: ComponentId(source),
            target: ComponentId(target),
            kind: kind
        )
    }

    private func threat(_ name: String, _ source: String, _ score: Int, sourceId: String? = nil) -> ReportThreat {
        ReportThreat(
            threatId: name,
            name: name,
            description: "",
            severityLabel: "High",
            riskScore: score,
            riskLevel: "high",
            strideLabels: [],
            mitreTechniqueIds: [],
            sourceName: source,
            sourceKind: "Component",
            // The other tests build with the default `nameOf`, which is the
            // identity, so a component's display name and id are the same
            // string there. This test's own `sourceId` overrides it.
            sourceId: sourceId ?? "component:\(source)",
            controls: [],
            pathwayMitigationLabels: []
        )
    }

    private func build(
        components: [Component],
        connections: [Connection],
        threats: [ReportThreat] = []
    ) -> (paths: [ReportAttackPath], notListed: Int) {
        AttackPaths.build(
            components: components,
            connections: connections,
            zones: [],
            threats: threats,
            nameOf: { $0.value }
        )
    }

    @Test func aModelWithNoSensitiveComponentHasNoPath() {
        let built = build(
            components: [component("a"), component("b")],
            connections: [flow("a", "b")]
        )
        #expect(built.paths.isEmpty)
    }

    @Test func aPathRunsFromAnEntryComponentToASensitiveOne() throws {
        let built = build(
            components: [component("actor"), component("api"), component("store", .restricted)],
            connections: [flow("actor", "api"), flow("api", "store")]
        )
        let path = try #require(built.paths.first)
        #expect(path.startName == "actor")
        #expect(path.endName == "store")
        #expect(path.hops.map(\.componentName) == ["actor", "api", "store"])
    }

    @Test func aHopNamesTheFlowKindItArrivedBy() throws {
        let built = build(
            components: [component("actor"), component("store", .restricted)],
            connections: [flow("actor", "store", .ipc)]
        )
        let path = try #require(built.paths.first)
        #expect(path.hops.first?.flowKindLabel == nil)
        #expect(path.hops.last?.flowKindLabel == "Local IPC")
    }

    @Test func aPathScoresAtItsWorstHop() throws {
        let built = build(
            components: [component("actor"), component("store", .restricted)],
            connections: [flow("actor", "store")],
            threats: [threat("weak", "actor", 3), threat("bad", "store", 12)]
        )
        let path = try #require(built.paths.first)
        #expect(path.worstScore == 12)
        #expect(path.hops.last?.worstThreatName == "bad")
    }

    @Test func aHopMatchesItsThreatByIdNotByDisplayName() throws {
        // "dupA" and "dupB" are two components of one technology with no
        // custom name, so nameOf gives both the same display name, "Duplicate".
        let names: [ComponentId: String] = [
            ComponentId("actor"): "actor",
            ComponentId("dupA"): "Duplicate",
            ComponentId("dupB"): "Duplicate"
        ]
        let built = AttackPaths.build(
            components: [
                component("actor"),
                Component(
                    id: ComponentId("dupA"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .restricted
                ),
                Component(
                    id: ComponentId("dupB"),
                    technologyId: TechnologyId("aws-ec2"),
                    position: Point(x: 0, y: 0),
                    sensitivity: .internalData
                )
            ],
            connections: [flow("actor", "dupA")],
            zones: [],
            threats: [
                threat("worst-on-other", "Duplicate", 20, sourceId: "component:dupB"),
                threat("actual", "Duplicate", 3, sourceId: "component:dupA")
            ],
            nameOf: { names[$0] ?? $0.value }
        )
        let path = try #require(built.paths.first)
        #expect(path.hops.last?.worstThreatName == "actual")
        #expect(path.hops.last?.riskScore == 3)
    }

    @Test func aCycleStopsTheWalk() {
        let built = build(
            components: [component("entry"), component("a"), component("b"), component("store", .restricted)],
            connections: [flow("entry", "a"), flow("a", "b"), flow("b", "a"), flow("b", "store")]
        )
        #expect(built.paths.isEmpty == false)
        #expect(built.paths.allSatisfy { $0.hops.count <= AttackPaths.maximumHops })
        #expect(built.paths.allSatisfy { $0.startName == "entry" })
    }

    @Test func aDiamondFindsBothRoutesToTheSameComponent() {
        let built = build(
            components: [
                component("actor"),
                component("left"),
                component("right"),
                component("store", .restricted)
            ],
            connections: [
                flow("actor", "left"),
                flow("actor", "right"),
                flow("left", "store"),
                flow("right", "store")
            ]
        )
        let endings = built.paths.map { $0.hops.map(\.componentName) }
        #expect(endings.contains(["actor", "left", "store"]))
        #expect(endings.contains(["actor", "right", "store"]))
    }

    @Test func aDiamondWithACycleInItStillFindsBothRoutes() {
        let built = build(
            components: [
                component("actor"),
                component("left"),
                component("right"),
                component("store", .restricted)
            ],
            connections: [
                flow("actor", "left"),
                flow("actor", "right"),
                flow("left", "store"),
                flow("right", "store"),
                flow("left", "right"),
                flow("right", "left")
            ]
        )
        let endings = built.paths.map { $0.hops.map(\.componentName) }
        #expect(endings.contains(["actor", "left", "store"]))
        #expect(endings.contains(["actor", "right", "store"]))
        #expect(built.paths.allSatisfy { $0.hops.count <= AttackPaths.maximumHops })
    }

    @Test func aChainLongerThanSixHopsStopsAtTheBound() {
        let built = build(
            components: [
                component("start"),
                component("n1"),
                component("n2"),
                component("n3"),
                component("n4"),
                component("n5"),
                component("n6"),
                component("store", .restricted)
            ],
            connections: [
                flow("start", "n1"),
                flow("n1", "n2"),
                flow("n2", "n3"),
                flow("n3", "n4"),
                flow("n4", "n5"),
                flow("n5", "n6"),
                flow("n6", "store")
            ]
        )
        #expect(built.paths.isEmpty)
        #expect(built.paths.allSatisfy { $0.hops.count <= AttackPaths.maximumHops })
    }

    @Test func theMarkdownStatesWhatItDidNotList() {
        let lines = MarkdownAttackPaths.lines([], notListed: 4)
        #expect(lines.contains("4 further paths are not listed."))
    }

    @Test func theMarkdownDrawsThePath() {
        let lines = MarkdownAttackPaths.lines(
            [
                ReportAttackPath(
                    startName: "actor",
                    endName: "store",
                    hops: [
                        ReportAttackPathHop(
                            componentName: "actor",
                            flowKindLabel: nil,
                            worstThreatName: nil,
                            riskScore: 0,
                            reducedBy: []
                        ),
                        ReportAttackPathHop(
                            componentName: "store",
                            flowKindLabel: "Local IPC",
                            worstThreatName: "Raw device read",
                            riskScore: 12,
                            reducedBy: ["ClearanceKit"]
                        )
                    ],
                    worstScore: 12
                )
            ],
            notListed: 0
        )
        #expect(lines.first == "## Attack paths")
        #expect(lines.contains("### actor \u{2192} store (worst 12)"))
        #expect(lines.contains("1. actor"))
        #expect(lines.contains("2. store, by Local IPC \u{2014} Raw device read (12), reduced by ClearanceKit"))
    }
}
