import FileGateways
import Foundation
import Testing
import ThreatModelKit
import TestSupport

struct ProjectSourceGatewayContractTests {
    @Test func theInMemoryProjectHonoursTheContract() {
        let project = InMemoryProject(root: "/project")

        verifyProjectSourceGatewayContract(
            root: "/project",
            put: { text, path in project.put(text, at: path) },
            make: { project }
        )
    }

    @Test func theFileSystemProjectHonoursTheContract() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("threat-modeller-project-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        verifyProjectSourceGatewayContract(
            root: root.path,
            put: { text, path in
                try? FileManager.default.createDirectory(
                    atPath: (path as NSString).deletingLastPathComponent,
                    withIntermediateDirectories: true
                )
                try? text.write(toFile: path, atomically: true, encoding: .utf8)
            },
            make: { FileSystemProject() }
        )
    }
}
