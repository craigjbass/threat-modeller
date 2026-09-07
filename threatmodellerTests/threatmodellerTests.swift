import Testing
import ThreatModelKit
@testable import threatmodeller

struct WiringTests {
    @Test func theTestTargetCanSeeThePackage() {
        #expect(threatModelKitIsWired)
    }
}
