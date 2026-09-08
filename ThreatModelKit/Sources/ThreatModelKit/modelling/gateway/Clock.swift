import Foundation

/// Reads the time. A use case that stamps a document takes one of these, so a
/// test can say what the time is.
public protocol Clock: Sendable {
    func now() -> Date
}

public struct SystemClock: Clock {
    public init() {}
    public func now() -> Date { Date() }
}
