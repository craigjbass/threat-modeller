import Testing
import ThreatModelKit
@testable import threatmodeller

/// The lines the threat card prints for every tree the threat is on.
///
/// The design
/// `docs/superpowers/specs/2026-09-17-trees-in-the-threat-list-design.md`
/// states the words.
@MainActor
@Suite("A threat card states the trees the threat is on")
struct ThreatCardTreeLinesTests {
    private func role(
        isGoal: Bool,
        open: Bool = true,
        stale: Bool = false,
        stepState: String? = nil,
        stepClosedBy: String? = nil,
        stepIsOpenBecause: String? = nil
    ) -> AssessedTreeRole {
        AssessedTreeRole(
            treeId: "read-every-record",
            treeName: "Read every customer record",
            isGoal: isGoal,
            isTreeOpen: open,
            isTreeStale: stale,
            raisesRiskBy: 40,
            scoreBefore: 5,
            score: open ? 7 : 5,
            stepState: stepState,
            stepClosedBy: stepClosedBy,
            stepIsOpenBecause: stepIsOpenBecause
        )
    }

    private func threat(
        _ roles: [AssessedTreeRole],
        controls: [AssessedControl] = []
    ) -> AssessedThreat {
        AssessedThreat(
            threatId: "credential-theft",
            name: "Credential theft",
            description: "",
            severityId: "high",
            severityLabel: "High",
            stride: [],
            mitreTechniques: [],
            controls: controls,
            source: .component(id: "api", name: "EC2", providerId: "aws"),
            sensitivityId: "confidential",
            riskScore: 7,
            riskLevel: "high",
            context: nil,
            isTlsMitigated: false,
            overrideKey: "k",
            overriddenSeverityId: nil,
            trees: roles
        )
    }

    @Test func aGoalNamesItsTreeAndTheBoostItGives() {
        #expect(ThreatCard.treeLines(threat([role(isGoal: true)])) == [
            "Goal of Read every customer record. The tree is open and raises this threat"
                + " by 40 per cent, 5 \u{2192} 7."
        ])
    }

    @Test func aGoalOfAClosedTreeSaysTheTreeRaisesNothing() {
        #expect(ThreatCard.treeLines(threat([role(isGoal: true, open: false)])) == [
            "Goal of Read every customer record. The tree is closed and raises nothing."
        ])
    }

    @Test func aGoalOfAStaleTreeSaysTheTreeIsStale() {
        #expect(ThreatCard.treeLines(threat([role(isGoal: true, stale: true)])) == [
            "Goal of Read every customer record. The tree is stale and raises nothing."
        ])
    }

    @Test func anOpenStepNamesItsRoleAndSaysWhyItIsOpen() {
        let lines = ThreatCard.treeLines(threat([
            role(
                isGoal: false,
                stepState: "open",
                stepIsOpenBecause: "an accepted control closes no step"
            )
        ]))

        #expect(lines == [
            "Step on Read every customer record. The tree is open and raises its goal"
                + " by 40 per cent. This step is open: an accepted control closes no step."
        ])
    }

    @Test func aClosedStepNamesTheControlThatClosedIt() {
        let lines = ThreatCard.treeLines(threat([
            role(isGoal: false, stepState: "closed", stepClosedBy: "Use IAM roles")
        ]))

        #expect(lines == [
            "Step on Read every customer record. The tree is open and raises its goal"
                + " by 40 per cent. This step is closed by Use IAM roles."
        ])
    }

    @Test func aThreatOnNoTreeStatesNoLine() {
        #expect(ThreatCard.treeLines(threat([])).isEmpty)
    }

    /// The card says which tree closing one control would break.
    @Test func aControlSaysWhichTreeClosingItWouldBreak() {
        let control = AssessedControl(
            description: "Use IAM roles",
            isTechnologySpecific: true,
            key: "k1",
            isImplemented: false,
            closesTreeNames: ["Read every customer record"]
        )

        #expect(ThreatCard.breaksTreeLines(control)
            == ["Closing this breaks the tree Read every customer record."])
        #expect(ThreatCard.breaksTreeLines(
            AssessedControl(description: "Other", isTechnologySpecific: false, key: "k2", isImplemented: false)
        ).isEmpty)
    }
}
