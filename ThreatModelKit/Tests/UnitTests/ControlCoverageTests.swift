import Testing
import ThreatModelKit
import TestSupport

struct ControlCoverageTests {
    private func control(_ description: String, _ status: ControlStatus) -> ResolvedControl {
        ResolvedControl(
            description: description,
            isTechnologySpecific: false,
            key: ControlKey(description),
            isImplemented: status == .implemented,
            status: status
        )
    }

    @Test func noControlsGiveNoCoverage() {
        #expect(ControlCoverage.coverage(of: []) == 0)
    }

    @Test func coverageIsTheImplementedShareOfTheApplicableControls() {
        let controls = [
            control("a", .implemented),
            control("b", .implemented),
            control("c", .notImplemented),
            control("d", .notImplemented),
            control("e", .notImplemented)
        ]
        #expect(ControlCoverage.coverage(of: controls) == 0.4)
    }

    @Test func aNotApplicableControlLeavesTheDenominator() {
        let controls = [
            control("a", .implemented),
            control("b", .notApplicable),
            control("c", .notImplemented)
        ]
        #expect(ControlCoverage.coverage(of: controls) == 0.5)
    }

    @Test func anAcceptedControlStaysInTheDenominatorAndLowersNothing() {
        let controls = [control("a", .accepted), control("b", .notImplemented)]
        #expect(ControlCoverage.coverage(of: controls) == 0)
    }

    @Test func threeOfFiveImplementedTakeTwelveToSeven() {
        let controls = [
            control("a", .implemented),
            control("b", .implemented),
            control("c", .implemented),
            control("d", .notImplemented),
            control("e", .notImplemented)
        ]
        #expect(ControlCoverage.apply(to: 12, controls: controls) == 7)
    }

    @Test func everyControlImplementedStillLeavesThirtyPercent() {
        let controls = [control("a", .implemented), control("b", .implemented)]
        #expect(ControlCoverage.apply(to: 10, controls: controls) == 3)
    }

    @Test func theScoreNeverFallsBelowOne() {
        let controls = [control("a", .implemented)]
        #expect(ControlCoverage.apply(to: 1, controls: controls) == 1)
    }
}

struct ControlCoverageInTheResolverTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func ec2() -> Component {
        Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .confidential
        )
    }

    /// The two technology-specific controls EC2 offers against credential
    /// theft. `CatalogueFixture.ec2()` declares both.
    private func key(_ description: String) -> ControlKey {
        ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: ThreatId("credential-theft"),
            description: description,
            isTechnologySpecific: true
        )
    }

    private func resolve(_ statuses: [ControlKey: ControlStatus]) -> ResolvedThreat {
        let model = ThreatModel(components: [ec2()], controlStatuses: statuses)
        let resolved = ThreatResolver(model: model, catalogue: catalogue).resolve()
        return resolved.first { $0.threat.id == ThreatId("credential-theft") }!
    }

    @Test func anUnansweredThreatKeepsItsScore() {
        let threat = resolve([:])
        #expect(threat.score.value == 12)
        #expect(threat.scoreBeforeControls == 12)
    }

    @Test func oneOfTwoControlsTakesTwelveToEight() {
        let threat = resolve([key("Enforce IMDSv2 to block SSRF-based credential theft"): .implemented])
        #expect(threat.score.value == 8)
        #expect(threat.scoreBeforeControls == 12)
    }

    @Test func bothControlsTakeTwelveToFour() {
        let threat = resolve([
            key("Enforce IMDSv2 to block SSRF-based credential theft"): .implemented,
            key("Use IAM roles with minimal permissions"): .implemented
        ])
        #expect(threat.score.value == 4)
    }

    @Test func anAcceptedControlChangesNothing() {
        let threat = resolve([key("Enforce IMDSv2 to block SSRF-based credential theft"): .accepted])
        #expect(threat.score.value == 12)
    }
}
