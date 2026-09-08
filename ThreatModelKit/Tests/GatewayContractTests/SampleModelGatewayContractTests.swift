import FileGateways
import Testing
import ThreatModelKit
import TestSupport

struct SampleModelGatewayContractTests {
    @Test func theFakeHonoursTheContract() {
        verifySampleModelGatewayContract { FakeSampleModels() }
    }

    @Test func theBundledSamplesHonourTheContract() {
        verifySampleModelGatewayContract { BundledSampleModels() }
    }
}
