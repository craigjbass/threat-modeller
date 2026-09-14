import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The order the threat list draws.
///
/// A person answers the register one card at a time, top to bottom, so the
/// order must hold still while they do. Worst first is right for the report
/// and for the first read; it is wrong to re-apply on every keystroke.
@MainActor
@Suite("The order the threat list holds")
struct ThreatListOrderTests {
    private func session() -> ThreatModelSession {
        ThreatModelSession(useCases: TestDependencies())
    }

    /// Two EC2 nodes, so the list holds six rows in two groups.
    private func twoNodes() -> ThreatModelSession {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-ec2", x: 400, y: 0)
        return session
    }

    private func sorted(_ session: ThreatModelSession) -> [String] {
        session.threats.map(\.threatKey)
    }

    @Test func startsWorstFirst() {
        let session = twoNodes()

        #expect(session.threats.map(\.riskScore) == session.threats.map(\.riskScore).sorted(by: >))
        #expect(session.rowsOutOfOrder == 0)
    }

    @Test func movesNoCardWhenAControlIsTicked() throws {
        let session = twoNodes()
        let before = sorted(session)
        let top = try #require(session.threats.first)
        let control = try #require(top.controls.first)

        session.setControl(key: control.key, implemented: true)

        #expect(sorted(session) == before)
        let after = try #require(session.threats.first { $0.threatKey == top.threatKey })
        #expect(after.riskScore < top.riskScore)
    }

    @Test func showsTheReorderButtonAfterAnEditThatChangesAScore() throws {
        let session = twoNodes()
        let control = try #require(session.threats.first?.controls.first)

        session.setControl(key: control.key, implemented: true)

        #expect(session.rowsOutOfOrder > 0)
    }

    @Test func movesNoCardWhenASeverityIsOverridden() throws {
        let session = twoNodes()
        let before = sorted(session)
        let top = try #require(session.threats.first)

        session.overrideSeverity(overrideKey: top.overrideKey, severityId: "low")

        #expect(sorted(session) == before)
        #expect(session.rowsOutOfOrder > 0)
    }

    @Test func movesNoCardWhenALikelihoodFindingIsWritten() throws {
        let session = twoNodes()
        let before = sorted(session)
        let top = try #require(session.threats.first)

        session.setLikelihoodFinding(
            threatKey: top.threatKey,
            label: "no in-the-wild use",
            tier: "research",
            prior: nil,
            rationale: "every report is researcher-found",
            sources: []
        )

        #expect(sorted(session) == before)
        #expect(session.rowsOutOfOrder > 0)
    }

    @Test func movesNoCardWhenACompensatingControlIsWritten() throws {
        let session = twoNodes()
        let before = sorted(session)
        let top = try #require(session.threats.first)

        session.setCompensatingControl(
            threatKey: top.threatKey,
            label: "the network blocks it",
            reducesRiskBy: 50,
            rationale: "the egress rule is in place"
        )

        #expect(sorted(session) == before)
    }

    @Test func sortsAndHidesTheButtonWhenTheUserReorders() throws {
        let session = twoNodes()
        let control = try #require(session.threats.first?.controls.first)
        session.setControl(key: control.key, implemented: true)
        #expect(session.rowsOutOfOrder > 0)

        session.resortThreats()

        #expect(session.threats.map(\.riskScore) == session.threats.map(\.riskScore).sorted(by: >))
        #expect(session.rowsOutOfOrder == 0)
    }

    @Test func sortsWithNoButtonWhenAModelLoads() throws {
        let session = twoNodes()
        let control = try #require(session.threats.first?.controls.first)
        session.setControl(key: control.key, implemented: true)
        #expect(session.rowsOutOfOrder > 0)

        session.loadSample(FakeSampleModels.sampleId)

        #expect(session.rowsOutOfOrder == 0)
        #expect(session.threats.map(\.riskScore) == session.threats.map(\.riskScore).sorted(by: >))
    }

    /// A threat the architecture newly raises enters at its sorted place, and
    /// neither adding nor removing shows the button on its own.
    @Test func entersANewThreatAtItsSortedPlace() throws {
        let session = session()
        session.add(technologyId: "aws-ec2", x: 0, y: 0)

        session.add(technologyId: "aws-rds", x: 400, y: 0)

        #expect(session.rowsOutOfOrder == 0)
        #expect(session.threats.map(\.riskScore) == session.threats.map(\.riskScore).sorted(by: >))
    }

    @Test func leavesTheRestWhenAThreatIsNoLongerRaised() throws {
        let session = twoNodes()
        let second = try #require(session.canvas.components.last?.id)

        _ = session.removeComponents([second])

        #expect(session.rowsOutOfOrder == 0)
        #expect(session.threats.allSatisfy { $0.source.id != "component:\(second)" })
    }

    /// The held order is a pure function of the rows and the order before it.
    @Test func keepsTheHeldOrderAndPlacesWhatIsNew() {
        let session = twoNodes()
        let assessed = session.threats
        let held = ThreatModelSession.held(
            assessed,
            inOrderOf: [assessed[2].threatKey, assessed[0].threatKey]
        )

        // Every row is there once, and the two the previous order named keep
        // the order it gave them.
        #expect(held.count == assessed.count)
        #expect(Set(held.map(\.threatKey)) == Set(assessed.map(\.threatKey)))
        let places = [assessed[2].threatKey, assessed[0].threatKey].compactMap { key in
            held.firstIndex { $0.threatKey == key }
        }
        #expect(places == places.sorted())
    }

    @Test func countsEveryRowASortWouldMove() {
        let session = twoNodes()
        let assessed = session.threats
        let swapped = [assessed[1], assessed[0]] + assessed.dropFirst(2)

        #expect(ThreatModelSession.rowsOutOfOrder(drawn: swapped, sorted: assessed) == 2)
        #expect(ThreatModelSession.rowsOutOfOrder(drawn: assessed, sorted: assessed) == 0)
    }
}

/// Opening and closing the groups of the threat list.
@MainActor
@Suite("The groups the threat list draws closed")
struct ThreatGroupCollapseTests {
    private func session() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        return session
    }

    private func groupIds(_ session: ThreatModelSession) -> [String] {
        var seen: [String] = []
        for threat in session.threats where seen.contains(threat.source.id) == false {
            seen.append(threat.source.id)
        }
        return seen
    }

    @Test func startsWithEveryGroupOpen() {
        #expect(session().collapsedGroups.isEmpty)
    }

    @Test func closesAndOpensOneGroup() throws {
        let session = session()
        let first = try #require(groupIds(session).first)

        session.toggleGroup(first)
        #expect(session.collapsedGroups == [first])

        session.toggleGroup(first)
        #expect(session.collapsedGroups.isEmpty)
    }

    @Test func closesEveryGroupAndOpensThemAgain() {
        let session = session()
        let ids = groupIds(session)
        #expect(ids.count == 2)

        session.collapseEveryGroup(ids)
        #expect(session.collapsedGroups == Set(ids))

        session.expandEveryGroup()
        #expect(session.collapsedGroups.isEmpty)
    }

    /// Option-clicking a group's disclosure does the same as the two buttons.
    @Test func closesEveryGroupOnAnOptionClickOfAnOpenGroup() throws {
        let session = session()
        let ids = groupIds(session)
        let first = try #require(ids.first)

        session.toggleGroup(first, everyGroupId: ids, appliesToEveryGroup: true)

        #expect(session.collapsedGroups == Set(ids))
    }

    @Test func opensEveryGroupOnAnOptionClickOfAClosedGroup() throws {
        let session = session()
        let ids = groupIds(session)
        let first = try #require(ids.first)
        session.collapseEveryGroup(ids)

        session.toggleGroup(first, everyGroupId: ids, appliesToEveryGroup: true)

        #expect(session.collapsedGroups.isEmpty)
    }

    /// The set lives on the session, so it survives every stage change and
    /// every edit for as long as the system is open.
    @Test func keepsTheClosedGroupsThroughAnEdit() throws {
        let session = session()
        let ids = groupIds(session)
        session.collapseEveryGroup(ids)
        let control = try #require(session.threats.first?.controls.first)

        session.setControl(key: control.key, implemented: true)

        #expect(session.collapsedGroups == Set(ids))
    }
}
