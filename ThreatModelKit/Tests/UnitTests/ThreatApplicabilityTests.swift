import Testing
import ThreatModelKit
import TestSupport

struct ThreatApplicabilityTests {
    private func threat(
        appliesTo: [FlowKind] = [],
        boundary: ZoneBoundary? = nil,
        runsAs: [PrivilegeLevel] = []
    ) -> Threat {
        Threat(
            id: ThreatId("t"),
            name: "T",
            description: "",
            severity: CatalogueFixture.high,
            isConnectionThreat: true,
            appliesToFlowKinds: appliesTo,
            boundary: boundary,
            appliesToPrivilegeLevels: runsAs
        )
    }

    @Test func aThreatThatNamesNoKindIsANetworkThreat() {
        let untagged = threat()
        #expect(ThreatApplicability.appliesToConnection(threat: untagged, kind: .network, crossesPrivilege: false))
        #expect(ThreatApplicability.appliesToConnection(threat: untagged, kind: .ipc, crossesPrivilege: false) == false)
        #expect(ThreatApplicability.appliesToConnection(threat: untagged, kind: .file, crossesPrivilege: false) == false)
    }

    @Test func aThreatIsRaisedOnTheKindsItNames() {
        let tagged = threat(appliesTo: [.file, .ipc])
        #expect(ThreatApplicability.appliesToConnection(threat: tagged, kind: .ipc, crossesPrivilege: false))
        #expect(ThreatApplicability.appliesToConnection(threat: tagged, kind: .network, crossesPrivilege: false) == false)
    }

    @Test func aPrivilegeThreatIsRaisedOnlyWhereTheFlowCrossesALevel() {
        let crossing = threat(boundary: .privilege)
        #expect(ThreatApplicability.appliesToConnection(threat: crossing, kind: .syscall, crossesPrivilege: true))
        #expect(ThreatApplicability.appliesToConnection(threat: crossing, kind: .syscall, crossesPrivilege: false) == false)
    }

    @Test func aPrivilegeBoundaryOnAConnectionThreatIgnoresAppliesTo() {
        // `boundary` is read before `applies_to`, so a connection threat
        // marked `boundary = .privilege` is raised only on a privilege
        // crossing, whatever flow kinds `applies_to` names.
        let crossing = threat(appliesTo: [.file, .ipc], boundary: .privilege)
        #expect(ThreatApplicability.appliesToConnection(threat: crossing, kind: .network, crossesPrivilege: true))
        #expect(ThreatApplicability.appliesToConnection(threat: crossing, kind: .file, crossesPrivilege: false) == false)
    }

    @Test func aZoneRaisesOnlyTheThreatsOfItsOwnBoundary() {
        #expect(ThreatApplicability.appliesToZone(threat: threat(), boundary: .network))
        #expect(ThreatApplicability.appliesToZone(threat: threat(), boundary: .privilege) == false)
        #expect(ThreatApplicability.appliesToZone(threat: threat(boundary: .privilege), boundary: .privilege))
        #expect(ThreatApplicability.appliesToZone(threat: threat(boundary: .privilege), boundary: .network) == false)
    }

    @Test func aComponentThreatThatNamesNoLevelIsRaisedAtEveryLevel() {
        #expect(ThreatApplicability.appliesToComponent(threat: threat(), runsAs: .user))
        #expect(ThreatApplicability.appliesToComponent(threat: threat(), runsAs: .kernel))
    }

    @Test func aComponentThreatIsRaisedOnlyAtTheLevelsItNames() {
        let rootOnly = threat(runsAs: [.root, .kernel])
        #expect(ThreatApplicability.appliesToComponent(threat: rootOnly, runsAs: .root))
        #expect(ThreatApplicability.appliesToComponent(threat: rootOnly, runsAs: .user) == false)
    }
}

/// Why a threat's matchers raised it, the text `AssessedThreat.matchReason`
/// carries to the card. The function reads the same six matchers
/// `ThreatApplicability` reads, and turns the ones that narrow where a
/// threat applies into one sentence.
struct ThreatMatchReasonTests {
    private func componentSource() -> ResolvedSource {
        .component(id: ComponentId("c1"), name: "API", providerId: ProviderId("aws"))
    }

    private func connectionSource() -> ResolvedSource {
        .connection(id: ConnectionId("f1"), sourceName: "API", targetName: "Store")
    }

    private func zoneSource() -> ResolvedSource {
        .zone(id: ZoneId("z1"), name: "DMZ")
    }

    @Test func aComponentThreatWithNoLevelNamesNoReason() {
        let threat = Threat(id: ThreatId("t"), name: "T", description: "", severity: CatalogueFixture.high)
        #expect(AssessThreatModel.matchReason(threat, source: componentSource()) == nil)
    }

    @Test func aComponentThreatRestrictedToLevelsNamesThem() {
        let threat = Threat(
            id: ThreatId("t"),
            name: "T",
            description: "",
            severity: CatalogueFixture.high,
            appliesToPrivilegeLevels: [.admin, .root]
        )
        #expect(
            AssessThreatModel.matchReason(threat, source: componentSource())
                == "Applies only where the component runs as Administrator or Root."
        )
    }

    @Test func aConnectionThreatRestrictedToOneFlowKindNamesIt() {
        let threat = Threat(
            id: ThreatId("t"),
            name: "T",
            description: "",
            severity: CatalogueFixture.high,
            isConnectionThreat: true,
            appliesToFlowKinds: [.ipc]
        )
        #expect(
            AssessThreatModel.matchReason(threat, source: connectionSource())
                == "Applies only to Local IPC flows."
        )
    }

    @Test func aPrivilegeCrossingConnectionThreatNamesTheCrossing() {
        let threat = Threat(
            id: ThreatId("t"),
            name: "T",
            description: "",
            severity: CatalogueFixture.high,
            isConnectionThreat: true,
            boundary: .privilege
        )
        #expect(
            AssessThreatModel.matchReason(threat, source: connectionSource())
                == "Applies only where the flow crosses a privilege level."
        )
    }

    @Test func aZoneThreatNamesItsBoundary() {
        let networkThreat = Threat(
            id: ThreatId("t"), name: "T", description: "", severity: CatalogueFixture.high, isZoneThreat: true
        )
        let privilegeThreat = Threat(
            id: ThreatId("t"),
            name: "T",
            description: "",
            severity: CatalogueFixture.high,
            isZoneThreat: true,
            boundary: .privilege
        )
        #expect(
            AssessThreatModel.matchReason(networkThreat, source: zoneSource())
                == "Applies within the network boundary."
        )
        #expect(
            AssessThreatModel.matchReason(privilegeThreat, source: zoneSource())
                == "Applies within the privilege boundary."
        )
    }

    @Test func aPathwayThreatNamesWhatItsScoreConsiders() {
        let threat = Threat(
            id: ThreatId("t"),
            name: "T",
            description: "",
            severity: CatalogueFixture.high,
            isPathwayThreat: true
        )
        #expect(
            AssessThreatModel.matchReason(threat, source: componentSource())
                == "Its sensitivity considers what this element feeds downstream, not only what it holds."
        )
    }
}

struct ThreatApplicabilityInTheResolverTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func component(_ id: String) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .confidential
        )
    }

    @Test func aLocalFlowRaisesNoNetworkThreat() {
        let model = ThreatModel(
            components: [component("a"), component("b")],
            connections: [
                Connection(
                    id: ConnectionId("a->b"),
                    source: ComponentId("a"),
                    target: ComponentId("b"),
                    kind: .ipc
                )
            ]
        )
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()
        #expect(resolved.contains { $0.threat.id == ThreatId("connection-mitm") } == false)
        #expect(resolved.contains { $0.threat.id == ThreatId("connection-dos") } == false)
    }

    @Test func aNetworkFlowStillRaisesTheNetworkThreats() {
        let model = ThreatModel(
            components: [component("a"), component("b")],
            connections: [
                Connection(id: ConnectionId("a->b"), source: ComponentId("a"), target: ComponentId("b"))
            ]
        )
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()
        #expect(resolved.contains { $0.threat.id == ThreatId("connection-mitm") })
    }
}

/// A library's own threat states matchers too, and they reach the card the
/// same way the vendored catalogue's do: through `AssessedThreat.matchReason`.
struct LibraryThreatMatcherReachesTheCardTests {
    private let library = """
    library "custom" {
      technology "widget" {
        name     = "Widget"
        category = "compute"
        threats  = ["custom-threat"]
      }

      threat "custom-threat" {
        name     = "Custom Threat"
        severity = "high"
        runs_as  = ["admin", "root"]
      }
    }
    """

    private let system = """
    system "Test" {
      component "api" {
        technology = "custom-widget"
        runs_as    = "admin"
      }
    }
    """

    @Test func aLibraryThreatsRunsAsMatcherReachesTheCard() throws {
        let app = TestDependencies()
        app.project.put(library, at: "/work/threatmodel/library/custom.lib")
        guard case .loaded(let libraries, _) = app.loadLibraries()
            .execute(LoadLibrariesRequest(root: "/work")) else {
            Issue.record("expected the library to load")
            return
        }
        app.useLibraries(libraries)
        _ = app.importArchitecture().execute(ImportArchitectureRequest(text: system))

        let threat = try #require(
            app.assessThreatModel().execute(AssessThreatModelRequest()).threats
                .first { $0.threatId == "custom-custom-threat" }
        )
        #expect(threat.matchReason == "Applies only where the component runs as Administrator or Root.")
    }
}
