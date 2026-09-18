import FileGateways
import Foundation
import Testing
import ThreatModelKit
import TestSupport

struct AttackDataGatewayContractTests {
    @Test func theInMemoryGatewayHonoursTheContract() {
        let gateway = InMemoryAttackData()

        verifyAttackDataGatewayContract(
            directory: gateway.directory,
            filesPresent: { gateway.fileNames },
            make: { gateway }
        )
    }

    @Test func theFileSystemGatewayHonoursTheContract() {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("threat-modeller-attack-\(UUID().uuidString)")
            .path
        defer { try? FileManager.default.removeItem(atPath: directory) }

        verifyAttackDataGatewayContract(
            directory: directory,
            filesPresent: { (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? [] },
            make: { FileSystemAttackData(directory: directory) }
        )
    }
}
