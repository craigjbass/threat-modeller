import Testing
import ThreatModelKit
import TestSupport

struct ConnectionEncryptionTests {
    private let plain = CatalogueFixture.ec2()            // enforcesEncryption == false
    private let encrypting = CatalogueFixture.rds()       // enforcesEncryption == true

    private func threat(_ id: String) -> Threat {
        Threat(
            id: ThreatId(id),
            name: id,
            description: "",
            severity: CatalogueFixture.medium,
            isConnectionThreat: true
        )
    }

    @Test func namesTheTwoThreatsTlsMitigates() {
        #expect(ConnectionEncryption.mitigatedThreatIds == [
            ThreatId("connection-mitm"),
            ThreatId("connection-data-exposure")
        ])
    }

    @Test func flagsAMitigableThreatWhenTheSourceEnforcesEncryption() {
        #expect(ConnectionEncryption.isTlsMitigated(
            threat: threat("connection-mitm"), source: encrypting, target: plain))
    }

    @Test func flagsAMitigableThreatWhenTheTargetEnforcesEncryption() {
        #expect(ConnectionEncryption.isTlsMitigated(
            threat: threat("connection-data-exposure"), source: plain, target: encrypting))
    }

    @Test func leavesAMitigableThreatUnflaggedWhenNeitherEndEnforcesEncryption() {
        #expect(ConnectionEncryption.isTlsMitigated(
            threat: threat("connection-mitm"), source: plain, target: plain) == false)
    }

    @Test func neverFlagsAThreatOutsideTheTwo() {
        #expect(ConnectionEncryption.isTlsMitigated(
            threat: threat("connection-dos"), source: encrypting, target: encrypting) == false)
    }

    @Test func treatsAnUnknownTechnologyAsNotEnforcingEncryption() {
        #expect(ConnectionEncryption.isTlsMitigated(
            threat: threat("connection-mitm"), source: nil, target: nil) == false)
        #expect(ConnectionEncryption.isTlsMitigated(
            threat: threat("connection-mitm"), source: nil, target: encrypting))
    }
}
