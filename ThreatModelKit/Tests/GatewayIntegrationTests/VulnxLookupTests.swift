import FileGateways
import Foundation
import Testing
import TestSupport
import ThreatModelKit

/// The real lookup, over a `vulnx` the test writes. No test runs the real tool.
@Suite("The vulnx lookup")
struct VulnxLookupTests {
    /// A directory holding one `vulnx` that prints one record.
    private func aDirectoryWithATool() throws -> String {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("tool-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let tool = directory.appendingPathComponent("vulnx")
        try ToolScript.write("""
        #!/bin/sh
        echo '{"cve_id":"CVE-2023-44487","cvss_score":7.5,"epss_score":0.94,"is_kev":true,"description":"HTTP/2 flood"}'

        """, to: tool.path)
        return directory.path
    }

    @Test func findsTheToolOnThePathItIsGiven() throws {
        let directory = try aDirectoryWithATool()

        let records = try VulnxLookup(path: directory).search(VulnerabilityQuery(product: "nginx", version: ""))

        #expect(records == [
            KnownVulnerability(
                id: "CVE-2023-44487",
                cvss: 7.5,
                epss: 0.94,
                isKnownExploited: true,
                summary: "HTTP/2 flood"
            )
        ])
    }

    @Test func aPathWithNoToolSaysTheToolIsNotInstalled() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("empty-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        #expect(throws: VulnerabilityLookupFault.toolIsNotInstalled) {
            try VulnxLookup(path: directory.path).search(VulnerabilityQuery(product: "nginx", version: ""))
        }
    }
}
