import ThreatModelKit

/// Stands in for the real renderer in tests. It writes the header a PDF starts
/// with and the model's name, which is everything the contract asks of it.
public struct FakeReportRenderer: ReportRenderer {
    public init() {}

    public func render(_ report: Report) throws -> [UInt8] {
        Array("%PDF-1.7\n\(report.modelName)\n%%EOF\n".utf8)
    }
}
