import Foundation

/// The libraries the open project holds.
///
/// A composition root builds its catalogue once, and a project's libraries
/// arrive later, when a user opens the project. The catalogue therefore reads
/// them through this rather than holding a copy.
public final class LibraryStore: @unchecked Sendable {
    private let lock = NSLock()
    private var libraries: [Library]

    public init(_ libraries: [Library] = []) {
        self.libraries = libraries
    }

    public func set(_ libraries: [Library]) {
        lock.lock()
        defer { lock.unlock() }
        self.libraries = libraries
    }

    public func all() -> [Library] {
        lock.lock()
        defer { lock.unlock() }
        return libraries
    }
}
