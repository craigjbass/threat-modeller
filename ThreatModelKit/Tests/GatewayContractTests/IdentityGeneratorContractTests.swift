import Testing
import ThreatModelKit
import TestSupport

/// Both generators keep the contract: the one a test runs on and the one the
/// application runs on.
@Suite("Every identity generator")
struct IdentityGeneratorContractTests {
    @Test func theSequentialOneHonoursTheContract() {
        verifyIdentityGeneratorContract(SequentialIdentityGenerator())
    }

    @Test func theOneTheApplicationUsesHonoursTheContract() {
        verifyIdentityGeneratorContract(UUIDIdentityGenerator())
    }
}
