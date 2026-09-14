import Foundation

/// Identifies a severity the user has overridden. Spec section 5.3.
///
/// A component threat is keyed by the **component**, so an override set on one
/// EC2 node stays on that node and leaves every other EC2 node alone. A link
/// override applies to every link and a zone override to every zone, because
/// the spec consolidates those two.
///
/// Every key carries the kind it belongs to as its first segment, so a
/// technology, a component or a zone named `connection` cannot write a key
/// another kind reads:
///
/// - component threat: `node:{componentId}::{threatId}`
/// - connection threat: `connection::{threatId}`
/// - zone threat: `zone::{threatId}`
///
/// The component shape carries `node:` before the id and `::` before the
/// threat id, and the other two carry no id at all, so no value of any id can
/// turn one shape into another.
public struct SeverityOverrideKey: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }

    public static func forComponent(componentId: ComponentId, threatId: ThreatId) -> SeverityOverrideKey {
        SeverityOverrideKey("node:\(componentId.value)::\(threatId.value)")
    }

    public static func forConnection(threatId: ThreatId) -> SeverityOverrideKey {
        SeverityOverrideKey("connection::\(threatId.value)")
    }

    public static func forZone(threatId: ThreatId) -> SeverityOverrideKey {
        SeverityOverrideKey("zone::\(threatId.value)")
    }

    /// Every override key belonging to one component starts with this.
    /// `RemoveComponents` prunes by it.
    public static func componentPrefix(_ componentId: ComponentId) -> String {
        "node:\(componentId.value)::"
    }
}

/// Reads the override keys a file written before the element keying holds.
///
/// A file written by an earlier build keys a component threat by its
/// technology: `{technologyId}::{threatId}`. That shape carries no kind, so it
/// is recognised by what it is not.
public enum SeverityOverrideMigration {
    /// The override keys of a loaded model, with every technology-keyed
    /// component override written once for each component of that technology.
    ///
    /// The old key is dropped, because nothing reads it again. A key the new
    /// shape already holds wins, so opening and saving twice changes nothing.
    public static func migrated(
        _ overrides: [SeverityOverrideKey: String],
        components: [Component]
    ) -> [SeverityOverrideKey: String] {
        var migrated: [SeverityOverrideKey: String] = [:]
        var carried: [SeverityOverrideKey: String] = [:]

        for (key, severityId) in overrides {
            guard let old = technologyKeyed(key) else {
                migrated[key] = severityId
                continue
            }
            for component in components where component.technologyId == old.technologyId {
                let now = SeverityOverrideKey.forComponent(
                    componentId: component.id,
                    threatId: old.threatId
                )
                carried[now] = severityId
            }
        }

        return carried.merging(migrated) { _, new in new }
    }

    /// The technology id and threat id of an old-shaped key, or nil when the
    /// key is one of the three shapes this build writes.
    private static func technologyKeyed(
        _ key: SeverityOverrideKey
    ) -> (technologyId: TechnologyId, threatId: ThreatId)? {
        if key.value.hasPrefix("node:") { return nil }
        if key.value.hasPrefix("connection::") { return nil }
        if key.value.hasPrefix("zone::") { return nil }

        let parts = key.value.components(separatedBy: "::")
        guard parts.count == 2, parts[0].isEmpty == false, parts[1].isEmpty == false else {
            return nil
        }
        return (TechnologyId(parts[0]), ThreatId(parts[1]))
    }
}
