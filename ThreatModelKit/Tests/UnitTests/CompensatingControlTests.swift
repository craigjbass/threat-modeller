import Testing
import ThreatModelKit
import TestSupport

@Suite("What a compensating control does to a score")
struct CompensatingControlTests {
    private let app = TestDependencies()

    @discardableResult
    private func aComponent(_ technologyId: String = "aws-ec2") -> String {
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: 0, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("the component was not added")
            return ""
        }
        return componentId
    }

    private func threats() -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats
    }

    private func compensate(
        _ key: ThreatKey,
        by percent: Int,
        label: String = "Watched by the SIEM"
    ) {
        app.modelStore.mutate { model in
            model.compensatingControls[key] = [
                CompensatingControl(
                    label: label,
                    reducesRiskBy: percent,
                    rationale: "It alerts on use."
                )
            ]
        }
    }

    @Test func lowersTheScoreOfTheThreatItAnswers() throws {
        let componentId = aComponent()
        let before = try #require(threats().first)

        compensate(ThreatKey(threatId: before.threatId, sourceId: "component:\(componentId)"), by: 40)

        let after = try #require(threats().first { $0.threatId == before.threatId })
        #expect(after.riskScore < before.riskScore)
        #expect(after.scoreBeforeCompensation == before.riskScore)
        #expect(after.compensatingLabels == ["Watched by the SIEM"])
    }

    @Test func leavesEveryOtherThreatAlone() throws {
        let componentId = aComponent()
        let all = threats()
        let first = try #require(all.first)
        let others = all.dropFirst().map(\.riskScore)

        compensate(ThreatKey(threatId: first.threatId, sourceId: "component:\(componentId)"), by: 50)

        #expect(threats().dropFirst().map(\.riskScore) == others)
    }

    @Test func givesTheStrongerOfTwoRatherThanTheSum() throws {
        let componentId = aComponent()
        let first = try #require(threats().first)
        let key = ThreatKey(threatId: first.threatId, sourceId: "component:\(componentId)")

        app.modelStore.mutate { model in
            model.compensatingControls[key] = [
                CompensatingControl(label: "one", reducesRiskBy: 30, rationale: "a"),
                CompensatingControl(label: "two", reducesRiskBy: 60, rationale: "b")
            ]
        }

        let after = try #require(threats().first { $0.threatId == first.threatId })
        // 60 percent off, not 90.
        #expect(after.riskScore == Int((Double(first.riskScore) * 0.4).rounded()))
    }

    @Test func neverTakesAScoreBelowOne() throws {
        let componentId = aComponent()
        let first = try #require(threats().first)

        compensate(
            ThreatKey(threatId: first.threatId, sourceId: "component:\(componentId)"),
            by: 100
        )

        #expect(try #require(threats().first { $0.threatId == first.threatId }).riskScore == 1)
    }

    @Test func saysNothingAboutAThreatNothingCompensates() throws {
        aComponent()

        let threat = try #require(threats().first)

        #expect(threat.compensatingLabels.isEmpty)
        #expect(threat.scoreBeforeCompensation == threat.riskScore)
    }

    @Test func countsTheLowerScoreInTheSummary() throws {
        let componentId = aComponent()
        let first = try #require(threats().first)
        let before = app.summariseRisk().execute(SummariseRiskRequest())

        compensate(
            ThreatKey(threatId: first.threatId, sourceId: "component:\(componentId)"),
            by: 90
        )

        let after = app.summariseRisk().execute(SummariseRiskRequest())
        #expect(after.totalThreats == before.totalThreats)
        // The threat is still raised, but it is no longer in the same band.
        #expect(after.byLevel != before.byLevel)
    }

    @Test func stillReadsImplementedControlsTheWayItDid() throws {
        aComponent()
        let control = try #require(threats().first?.controls.first)

        _ = app.recordControlImplemented().execute(
            RecordControlImplementedRequest(controlKey: control.key)
        )

        let after = try #require(threats().first?.controls.first { $0.key == control.key })
        #expect(after.isImplemented)
        #expect(after.statusId == "implemented")
        #expect(after.statusLabel == "Implemented")
        #expect(app.summariseRisk().execute(SummariseRiskRequest()).controlsRecorded == 1)
    }
}
