import Foundation

/// One bundled example, named for a browser and read on demand.
public struct SampleModel: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String

    public init(id: String, name: String, description: String) {
        self.id = id
        self.name = name
        self.description = description
    }
}

public enum SampleModelError: Error, Equatable, Sendable {
    case unknownSample(id: String)
    case unreadable(reason: String)
}

/// Lists and loads the examples this application ships.
///
/// A sample is a document, read by the same codec a user's own file goes
/// through, so a sample that stopped opening is a document format defect.
public protocol SampleModelGateway: Sendable {
    func all() -> [SampleModel]
    func document(id: String) throws -> Data
}
