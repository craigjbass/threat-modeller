import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The session is the delivery mechanism's translator. These tests run it on
/// the fake catalogue, not the vendored one: a catalogue update must never
/// break a delivery-mechanism test.
@MainActor
struct ThreatModelSessionTests {
    private func session() -> ThreatModelSession {
        ThreatModelSession(useCases: TestDependencies())
    }

    @Test func loadsThePaletteOnLaunch() {
        let session = session()

        #expect(session.palette.map(\.id) == ["aws", "gcp"])
        #expect(session.threats.isEmpty)
    }

    @Test func raisesScoredThreatsWhenATechnologyIsAdded() {
        let session = session()

        session.add(technologyId: "aws-ec2")

        #expect(session.threats.map(\.threatId) == [
            "credential-theft",
            "misconfiguration",
            "dos-attack"
        ])
        #expect(session.threats.first?.riskScore == 8)
        #expect(session.threats.first?.riskLevel == "high")
        #expect(session.errorMessage == nil)
    }

    @Test func reportsATechnologyThatIsNotInTheCatalogue() {
        let session = session()

        session.add(technologyId: "aws-imaginary")

        #expect(session.threats.isEmpty)
        #expect(session.errorMessage == "That technology is not in the catalogue.")
    }
}
