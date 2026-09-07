import Testing
import ThreatModelKit
@testable import threatmodeller

struct WiringTests {
    @Test func theTestTargetCanSeeThePackage() {
        let severity = ThreatSeverity(id: "high", label: "High", rank: 3)
        #expect(severity.rank == 3)
    }
}
