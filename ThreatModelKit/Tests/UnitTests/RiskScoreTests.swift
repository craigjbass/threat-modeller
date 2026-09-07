import Testing
import ThreatModelKit
import TestSupport

struct RiskScoreTests {
    @Test func multipliesSeverityRankBySensitivityRank() {
        #expect(RiskScore(severity: CatalogueFixture.critical, sensitivity: .restricted).value == 16)
        #expect(RiskScore(severity: CatalogueFixture.low, sensitivity: .publicData).value == 1)
        #expect(RiskScore(severity: CatalogueFixture.high, sensitivity: .confidential).value == 9)
        #expect(RiskScore(severity: CatalogueFixture.medium, sensitivity: .internalData).value == 4)
    }

    @Test func callsTwelveAndAboveCritical() {
        #expect(RiskScore(value: 12).level == .critical)
        #expect(RiskScore(value: 16).level == .critical)
    }

    @Test func callsEightToElevenHigh() {
        #expect(RiskScore(value: 8).level == .high)
        #expect(RiskScore(value: 11).level == .high)
    }

    @Test func callsFourToSevenMedium() {
        #expect(RiskScore(value: 4).level == .medium)
        #expect(RiskScore(value: 7).level == .medium)
    }

    @Test func callsBelowFourLow() {
        #expect(RiskScore(value: 3).level == .low)
        #expect(RiskScore(value: 1).level == .low)
        #expect(RiskScore(value: 0).level == .low)
    }
}
