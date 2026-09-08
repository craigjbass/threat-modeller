import Testing
import ThreatModelKit
@testable import threatmodeller

@MainActor
struct ThreatModelSessionTests {
    @Test func loadsTheWholeCataloguePaletteOnLaunch() throws {
        let session = ThreatModelSession(useCases: try Dependencies())

        #expect(session.palette.map(\.id) == ["aws", "azure", "gcp", "saas", "self-hosted"])
        #expect(session.threats.isEmpty)
    }

    @Test func raisesScoredThreatsWhenATechnologyIsAdded() throws {
        let session = ThreatModelSession(useCases: try Dependencies())

        session.add(technologyId: "aws-ec2")

        #expect(session.threats.count == 10)
        #expect(session.threats.first?.threatId == "credential-theft")
        #expect(session.threats.first?.riskScore == 8)
        #expect(session.threats.first?.riskLevel == "high")
        #expect(session.errorMessage == nil)
    }

    @Test func reportsATechnologyThatIsNotInTheCatalogue() throws {
        let session = ThreatModelSession(useCases: try Dependencies())

        session.add(technologyId: "aws-imaginary")

        #expect(session.threats.isEmpty)
        #expect(session.errorMessage == "That technology is not in the catalogue.")
    }
}
