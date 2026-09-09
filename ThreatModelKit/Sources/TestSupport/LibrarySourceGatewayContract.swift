import Testing
import ThreatModelKit

/// The one contract every library source gateway meets.
public func assertLibrarySourceGateway(_ gateway: LibrarySourceGateway) {
    let text = """
    library "acme" {
      technology "cribl-stream" {
        name     = "Cribl Stream"
        category = "monitoring"
        threats  = ["pipeline-tamper"]
      }

      threat "pipeline-tamper" {
        name     = "Pipeline tampering"
        severity = "high"

        control "Sign pipeline configurations"
      }
    }

    """

    let read = gateway.read(text)
    #expect(read.hasErrors == false)
    #expect(read.source?.label == "acme")
    #expect(read.source?.technologies.map(\.id) == ["cribl-stream"])
    #expect(read.source?.threats.map(\.id) == ["pipeline-tamper"])

    // Writing what it read reproduces the file, byte for byte.
    if let source = read.source {
        #expect(gateway.write(source) == text)
    }

    let refused = gateway.read("system \"Payments\" { }")
    #expect(refused.source == nil)
    #expect(refused.hasErrors)
}
