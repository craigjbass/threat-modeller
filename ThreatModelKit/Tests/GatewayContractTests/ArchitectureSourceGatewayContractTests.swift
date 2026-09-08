import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

struct ArchitectureSourceGatewayContractTests {
    @Test func theFakeHonoursTheContract() {
        verifyArchitectureSourceGatewayContract { FakeArchitectureSource() }
    }

    @Test func theRealLanguageHonoursTheContract() {
        verifyArchitectureSourceGatewayContract { HclArchitectureSource() }
    }
}
