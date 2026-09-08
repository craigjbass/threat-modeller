import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

struct ControlsSourceGatewayContractTests {
    @Test func theFakeHonoursTheContract() {
        verifyControlsSourceGatewayContract { FakeControlsSource() }
    }

    @Test func theRealLanguageHonoursTheContract() {
        verifyControlsSourceGatewayContract { HclControlsSource() }
    }
}
