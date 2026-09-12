/// A component that answers threats on another element through a `mitigates`
/// edge.
///
/// This is what a reader means by "a control at the boundary": a product or a
/// gateway that stands in the way, named on the diagram. A control the user
/// ticked on a threat is not one of these, because nothing on the diagram
/// gives it.
public struct EdgeGuard: Equatable, Sendable {
    /// The protecting component's name.
    public let label: String
    /// True when the edge is assumed. An assumed edge lowers the target
    /// posture and never the residual score, so a reader must never take it
    /// for work that is done.
    public let isAssumed: Bool

    public init(label: String, isAssumed: Bool) {
        self.label = label
        self.isAssumed = isAssumed
    }
}

/// What guards each element on the diagram.
///
/// The canvas draws these beside the trust boundary a flow crosses, so a
/// reader sees what stands in the way without opening a panel.
public enum EdgeGuards {
    /// Keyed by source id: "component:<id>", "connection:<id>" or
    /// "zone:<id>". An element that no edge guards holds no entry.
    ///
    /// A component named by both an adopted edge and an assumed one is
    /// reported adopted, because the stronger claim is the true one. The
    /// order is by label, so the same model draws the same picture.
    public static func byElement(_ threats: [AssessedThreat]) -> [String: [EdgeGuard]] {
        var adopted: [String: Set<String>] = [:]
        var assumed: [String: Set<String>] = [:]

        for threat in threats {
            let sourceId = threat.source.id
            adopted[sourceId, default: []].formUnion(threat.mitigatedByComponentLabels)
            assumed[sourceId, default: []].formUnion(threat.assumedByComponentLabels)
        }

        var built: [String: [EdgeGuard]] = [:]

        for sourceId in Set(adopted.keys).union(assumed.keys) {
            let adoptedLabels = adopted[sourceId] ?? []
            let assumedLabels = (assumed[sourceId] ?? []).subtracting(adoptedLabels)
            let guards =
                (adoptedLabels.map { EdgeGuard(label: $0, isAssumed: false) }
                    + assumedLabels.map { EdgeGuard(label: $0, isAssumed: true) })
                .sorted { $0.label < $1.label }

            guard guards.isEmpty == false else { continue }
            built[sourceId] = guards
        }

        return built
    }

    /// Two guard lists read as one. A label in both is named once, and adopted
    /// beats assumed, so a reader never sees the same component twice or takes
    /// a plan for work that is done.
    public static func merge(_ first: [EdgeGuard], _ second: [EdgeGuard]) -> [EdgeGuard] {
        let all = first + second
        let adopted = Set(all.filter { $0.isAssumed == false }.map(\.label))
        let assumed = Set(all.filter(\.isAssumed).map(\.label)).subtracting(adopted)

        return (adopted.map { EdgeGuard(label: $0, isAssumed: false) }
            + assumed.map { EdgeGuard(label: $0, isAssumed: true) })
            .sorted { $0.label < $1.label }
    }
}
