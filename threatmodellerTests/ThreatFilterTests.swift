import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// What the sidebar's search field and filter keep.
@MainActor
@Suite("Narrowing the threat list")
struct ThreatFilterTests {
    private func session() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        return session
    }

    @Test func keepsEveryThreatWhenNothingIsTyped() {
        let threats = session().threats

        #expect(ThreatFilter().narrow(threats).count == threats.count)
        #expect(ThreatFilter().isNarrowing == false)
    }

    @Test func narrowsByTheThreatsTitle() {
        let threats = session().threats
        var filter = ThreatFilter()
        filter.text = "credential"

        let kept = filter.narrow(threats)

        #expect(kept.isEmpty == false)
        #expect(kept.allSatisfy { $0.threatId == "credential-theft" })
    }

    @Test func narrowsByTheElementsName() {
        let threats = session().threats
        var filter = ThreatFilter()
        filter.text = "rds"

        let kept = filter.narrow(threats)

        #expect(kept.isEmpty == false)
        #expect(kept.allSatisfy { $0.source.displayName.lowercased().contains("rds") })
    }

    @Test func narrowsByWhatTheThreatHarms() {
        let threats = session().threats
        var filter = ThreatFilter()
        filter.impactId = ThreatImpact.availability.rawValue

        let kept = filter.narrow(threats)

        #expect(kept.isEmpty == false)
        #expect(kept.count < threats.count)
        #expect(kept.allSatisfy { $0.impacts.contains("availability") })
        #expect(filter.isNarrowing)
    }

    @Test func narrowsByTheThreatId() {
        let threats = session().threats
        var filter = ThreatFilter()
        filter.text = "dos-attack"

        #expect(filter.narrow(threats).allSatisfy { $0.threatId == "dos-attack" })
    }

    @Test func ignoresCaseAndSurroundingSpace() {
        let threats = session().threats
        var filter = ThreatFilter()
        filter.text = "  CREDENTIAL  "

        #expect(filter.narrow(threats).isEmpty == false)
    }

    @Test func narrowsByRiskLevel() {
        let threats = session().threats
        var filter = ThreatFilter()
        filter.levelId = "high"

        let kept = filter.narrow(threats)

        #expect(kept.isEmpty == false)
        #expect(kept.allSatisfy { $0.riskLevel == "high" })
    }

    @Test func narrowsByStrideCategory() {
        let threats = session().threats
        var filter = ThreatFilter()
        filter.strideId = "spoofing"

        let kept = filter.narrow(threats)

        #expect(kept.isEmpty == false)
        #expect(kept.allSatisfy { $0.stride.contains("spoofing") })
    }

    @Test func narrowsByWhetherTheThreatIsAnswered() throws {
        let session = session()
        let control = try #require(session.threats.first?.controls.first)
        let answeredKey = try #require(session.threats.first?.threatKey)
        session.setControl(key: control.key, implemented: true)

        var answered = ThreatFilter()
        answered.answered = .answered
        var unanswered = ThreatFilter()
        unanswered.answered = .unanswered

        #expect(answered.narrow(session.threats).map(\.threatKey) == [answeredKey])
        #expect(unanswered.narrow(session.threats).contains { $0.threatKey == answeredKey } == false)
        #expect(
            answered.narrow(session.threats).count
                + unanswered.narrow(session.threats).count == session.threats.count
        )
    }

    @Test func keepsNothingWhenNothingMatches() {
        var filter = ThreatFilter()
        filter.text = "no such threat"

        #expect(filter.narrow(session().threats).isEmpty)
        #expect(filter.isNarrowing)
    }

    @Test func restoresEveryThreatWhenTheFilterIsCleared() {
        let threats = session().threats
        var filter = ThreatFilter()
        filter.text = "credential"
        filter.levelId = "high"

        filter = ThreatFilter()

        #expect(filter.narrow(threats).count == threats.count)
    }

    /// The summary counts the whole model, whatever the filter hides.
    @Test func leavesTheRiskSummaryCountingTheWholeModel() throws {
        let session = session()
        var filter = ThreatFilter()
        filter.text = "credential"

        #expect(filter.narrow(session.threats).count < session.threats.count)
        #expect(session.summary.totalThreats == session.threats.count)
    }
}
