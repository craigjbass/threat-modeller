import Foundation

/// Finds a project's files, and reads and writes them.
///
/// The convention lives here, in one place, so the application and the
/// executable cannot disagree about where a file is.
public protocol ProjectSourceGateway: Sendable {
    /// The directory this application looks in first.
    static var conventionDirectory: String { get }

    func discover(root: String) throws -> ProjectLayout
    func read(path: String) throws -> String
    func write(_ text: String, to path: String) throws
    /// Writes bytes rather than text. A picture is not text.
    func write(bytes: Data, to path: String) throws
    /// Removes a file. A file that is not there is not a fault, because the
    /// caller wanted it gone and it is gone.
    func delete(path: String) throws
    func exists(path: String) -> Bool
}

public extension ProjectSourceGateway {
    static var conventionDirectory: String { "threatmodel" }
}
