import Testing
import ThreatModelKit

struct VocabularyTests {
    @Test func aFlowIsANetworkFlowUnlessItSaysOtherwise() {
        #expect(FlowKind.default == .network)
        #expect(FlowKind(rawValue: "ipc") == .ipc)
        #expect(FlowKind.allCases.count == 5)
    }

    @Test func thePrivilegeLadderRuns() {
        #expect(PrivilegeLevel.user.rank < PrivilegeLevel.root.rank)
        #expect(PrivilegeLevel.root.rank < PrivilegeLevel.kernel.rank)
    }

    @Test func aZoneIsANetworkBoundaryUnlessItSaysOtherwise() {
        #expect(Zone(id: ZoneId("z"), rect: Rect(x: 0, y: 0, width: 200, height: 200)).boundary == .network)
    }

    @Test func aComponentRunsAsTheUserUnlessItSaysOtherwise() {
        #expect(component().runsAs == .user)
    }

    @Test func aComponentWithNoAssetScoresAtItsOwnSensitivity() {
        #expect(component().effectiveSensitivity == .internalData)
    }

    @Test func aComponentScoresAtItsHighestAsset() {
        let held = component(assets: [
            Asset(name: "cookies", sensitivity: .confidential),
            Asset(name: "ssh-keys", sensitivity: .restricted)
        ])
        #expect(held.effectiveSensitivity == .restricted)
    }

    @Test func anAssetNeverLowersTheComponentsOwnSensitivity() {
        let held = component(
            sensitivity: .restricted,
            assets: [Asset(name: "notes", sensitivity: .publicData)]
        )
        #expect(held.effectiveSensitivity == .restricted)
    }

    private func component(
        sensitivity: DataSensitivity = .internalData,
        assets: [Asset] = []
    ) -> Component {
        Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: sensitivity,
            assets: assets
        )
    }
}
