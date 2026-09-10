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

    private func threat(_ name: String, _ source: String, _ score: Int) -> ReportThreat {
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

    @Test func aCycleStopsTheWalk() {
        let built = build(
            components: [component("a"), component("b"), component("store", .restricted)],
            connections: [flow("a", "b"), flow("b", "a"), flow("b", "store")]
        )
        #expect(built.paths.isEmpty == false)
        #expect(built.paths.allSatisfy { $0.hops.count <= AttackPaths.maximumHops })
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
