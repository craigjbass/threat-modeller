import Testing
import ThreatModelKit
import TestSupport

struct ThreatModelGatewayContractTests {
    @Test func theInMemoryStoreHonoursTheContract() {
        verifyThreatModelGatewayContract { InMemoryThreatModelGateway() }
    }
}
