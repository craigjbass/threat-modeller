/// Turns a report tree into PDF bytes.
///
/// The core decides what a report says; this port decides how a page looks.
/// Spec section 12: page layout is checked by eye and is not unit tested.
public protocol ReportRenderer: Sendable {
    func render(_ report: Report) throws -> [UInt8]
}

public enum ReportRenderError: Error, Equatable, Sendable {
    /// The renderer could not start a document. Nothing else can go wrong that
    /// a caller can act on.
    case cannotStartDocument
}
