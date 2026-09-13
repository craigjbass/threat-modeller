import Foundation
import ThreatModelKit

/// Yields "id-1", "id-2", … so tests can assert on identifiers.
///
/// Locked, because a use case may run off the main actor and this stands where
/// the real generator does.
public final class SequentialIdentityGenerator: IdentityGenerator, @unchecked Sendable {
    private let lock = NSLock()
    private var issued = 0

    public init() {}

    public func next() -> String {
        lock.lock()
        defer { lock.unlock() }
        issued += 1
        return "id-\(issued)"
    }
}
