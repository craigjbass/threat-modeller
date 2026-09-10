/// Every way in, to everything worth taking.
///
/// Spec section 9. The report already scores each threat on its own; this is
/// the story that joins them, which is what a reader asks for first: how does
/// an attacker get from the outside to the restricted data, and what stops
/// them on the way.
public enum AttackPaths {
    /// A path longer than this is a story nobody reads.
    public static let maximumHops = 6
    /// The report lists this many, worst first, and states what it dropped.
    public static let maximumPaths = 20

    public static func build(
        components: [Component],
        connections: [Connection],
        zones: [Zone],
        threats: [ReportThreat],
        nameOf: (ComponentId) -> String
    ) -> (paths: [ReportAttackPath], notListed: Int) {
        guard components.isEmpty == false else { return ([], 0) }

        var forward: [ComponentId: [Connection]] = [:]
        var hasInbound: Set<ComponentId> = []
        for connection in connections {
            forward[connection.source, default: []].append(connection)
            hasInbound.insert(connection.target)
        }

        let publicZones = zones.filter { $0.networkZone == .publicZone }
        let starts = components.filter { component in
            hasInbound.contains(component.id) == false
                || ZoneContainment.zone(holding: component.centre, in: publicZones) != nil
        }
        let ends = Set(
            components
                .filter { $0.effectiveSensitivity == .confidential || $0.effectiveSensitivity == .restricted }
                .map(\.id)
        )
        guard ends.isEmpty == false else { return ([], 0) }

        var found: [ReportAttackPath] = []

        func walk(
            _ component: ComponentId,
            _ arrivedBy: Connection?,
            _ hops: [ReportAttackPathHop],
            _ seen: Set<ComponentId>
        ) {
            let hop = self.hop(
                component,
                arrivedBy: arrivedBy,
                threats: threats,
                nameOf: nameOf
            )
            let path = hops + [hop]

            if ends.contains(component) && path.count > 1 {
                found.append(
                    ReportAttackPath(
                        startName: path[0].componentName,
                        endName: hop.componentName,
                        hops: path,
                        worstScore: path.map(\.riskScore).max() ?? 0
                    )
                )
            }
            guard path.count < maximumHops else { return }

            for next in forward[component] ?? [] where seen.contains(next.target) == false {
                walk(next.target, next, path, seen.union([next.target]))
            }
        }

        for start in starts {
            walk(start.id, nil, [], [start.id])
        }

        let ordered = found.sorted { left, right in
            if left.worstScore != right.worstScore { return left.worstScore > right.worstScore }
            if left.hops.count != right.hops.count { return left.hops.count < right.hops.count }
            return left.endName < right.endName
        }

        return (
            Array(ordered.prefix(maximumPaths)),
            max(0, ordered.count - maximumPaths)
        )
    }

    /// One step of the story: what the attacker reached, how they got there,
    /// and the worst thing that is still open on it.
    private static func hop(
        _ component: ComponentId,
        arrivedBy: Connection?,
        threats: [ReportThreat],
        nameOf: (ComponentId) -> String
    ) -> ReportAttackPathHop {
        let name = nameOf(component)
        let sourceId = "component:\(component.value)"
        let worst = threats
            .filter { $0.sourceKind == "Component" && $0.sourceId == sourceId }
            .max { $0.riskScore < $1.riskScore }

        return ReportAttackPathHop(
            componentName: name,
            flowKindLabel: arrivedBy.map(\.kind.label),
            worstThreatName: worst?.name,
            riskScore: worst?.riskScore ?? 0,
            reducedBy: (worst?.pathwayMitigationLabels ?? []) + (worst?.mitigatedByComponentLabels ?? [])
        )
    }
}
