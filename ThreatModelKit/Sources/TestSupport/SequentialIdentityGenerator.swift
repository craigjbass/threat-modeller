import ThreatModelKit

/// Yields "id-1", "id-2", … so tests can assert on identifiers.
public final class SequentialIdentityGenerator: IdentityGenerator {
    private var issued = 0

    public init() {}

    public func next() -> String {
        issued += 1
        return "id-\(issued)"
    }
}
