/// Which components feed which. Spec section 5.2.
///
/// A pathway mitigation belongs to whatever sits in front of a component, so
/// the assessment has to walk the links backwards. A pathway threat escalates
/// to what it feeds, so it also has to look one hop forwards.
public struct UpstreamGraph {
    private let sourcesByTarget: [ComponentId: [ComponentId]]
    private let targetsBySource: [ComponentId: [ComponentId]]

    public init(connections: [Connection]) {
        var sources: [ComponentId: [ComponentId]] = [:]
        var targets: [ComponentId: [ComponentId]] = [:]
        for connection in connections {
            sources[connection.target, default: []].append(connection.source)
            targets[connection.source, default: []].append(connection.target)
        }
        sourcesByTarget = sources
        targetsBySource = targets
    }

    /// Every component that reaches this one by any number of hops.
    ///
    /// Strict: a component is never upstream of itself, even in a cycle, so a
    /// component never mitigates its own threats. The walk marks what it has
    /// seen, so a cycle finishes rather than looping.
    public func upstream(of component: ComponentId) -> Set<ComponentId> {
        var found: Set<ComponentId> = []
        var queue = sourcesByTarget[component] ?? []

        while let next = queue.popLast() {
            guard next != component else { continue }
            guard found.contains(next) == false else { continue }
            found.insert(next)
            queue.append(contentsOf: sourcesByTarget[next] ?? [])
        }

        return found
    }

    /// The components one hop forward. A pathway threat escalates to the data
    /// these hold, not to everything further on.
    public func directlyDownstream(of component: ComponentId) -> Set<ComponentId> {
        Set(targetsBySource[component] ?? [])
    }
}
