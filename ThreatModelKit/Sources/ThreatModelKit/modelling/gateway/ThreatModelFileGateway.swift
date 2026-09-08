import Foundation

public enum ThreatModelFileError: Error, Equatable {
    /// The file says it is a version this application does not read. Refusing
    /// is the point: guessing at an unknown shape loses the user's work
    /// quietly, and a later version can always be taught to read it.
    case unsupportedFormatVersion(found: Int, supported: Int)
    /// A value outside the vocabulary — a sensitivity, a zone kind, a network
    /// type or a mitigation mode this application does not have.
    case unknownValue(field: String, value: String)
}

/// Turns a model into the bytes of a document, and back.
///
/// The only thing that crosses this boundary is `Data`. The core never opens a
/// file, and the delivery mechanism never sees a Domain object.
public protocol ThreatModelFileGateway: Sendable {
    func encode(_ model: ThreatModel) throws -> Data
    func decode(_ data: Data) throws -> ThreatModel
    /// A selection as clipboard text, so it crosses documents and copies of the
    /// application, and a person can read it.
    func encodeSelection(_ selection: SelectionSnippet) throws -> String
    func decodeSelection(_ text: String) throws -> SelectionSnippet
}
