/// Every way in, to everything worth taking.
///
/// Spec section 9. The report already scores each threat on its own; this is
/// the story that joins them, which is what a reader asks for first: how does
/// an attacker get from the outside to the restricted data, and what stops
/// them on the way.
public enum AttackPaths {
    /// A path longer than this is a story nobody reads.
    public static let maximumHops = 6
    /// The narrative carries this many, worst first, and states what it left.
    public static let narratedPaths = 5
    /// The trace keeps this many before it curates them.
    public static let maximumPaths = 20

    public static func build(
        components: [Component],
        connections: [Connection],
        zones: [Zone],
        threats: [ReportThreat],
        nameOf: (ComponentId) -> String
    ) -> (
        paths: [ReportAttackPath],
        prefix: [ReportAttackPathHop],
        notListed: [ReportAttackPathSummary],
        beyond: Int
    ) {
        guard components.isEmpty == false else { return ([], [], [], 0) }

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
        guard ends.isEmpty == false else { return ([], [], [], 0) }

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
                let worstScore = path.map(\.riskScore).max() ?? 0
                let worstHop = path.first { $0.riskScore == worstScore }
                let likelihood = threats
                    .first { $0.name == worstHop?.worstThreatName }?
                    .likelihoodLabel ?? ""
                found.append(
                    ReportAttackPath(
                        startName: path[0].componentName,
                        endName: hop.componentName,
                        hops: path,
                        worstScore: worstScore,
                        likelihoodLabel: likelihood
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

        return curate(
            Array(ordered.prefix(maximumPaths)),
            beyond: max(0, ordered.count - maximumPaths)
        )
    }

    /// Turns a list of traced paths into a story: five paths, the steps they
    /// all share stated once, a line for everything left, and the count of
    /// what the trace found beyond even that.
    public static func curate(
        _ ordered: [ReportAttackPath],
        beyond: Int
    ) -> (
        paths: [ReportAttackPath],
        prefix: [ReportAttackPathHop],
        notListed: [ReportAttackPathSummary],
        beyond: Int
    ) {
        let listed = Array(ordered.prefix(narratedPaths))
        let notListed = ordered.dropFirst(narratedPaths).map {
            ReportAttackPathSummary(
                startName: $0.startName,
                endName: $0.endName,
                worstScore: $0.worstScore
            )
        }
        guard listed.count > 1 else { return (listed, [], Array(notListed), beyond) }

        let prefix = sharedPrefix(of: listed)
        guard prefix.isEmpty == false else { return (listed, [], Array(notListed), beyond) }

        let trimmed = listed.map { path in
            ReportAttackPath(
                startName: path.startName,
                endName: path.endName,
                hops: Array(path.hops.dropFirst(prefix.count)),
                worstScore: path.worstScore,
                likelihoodLabel: path.likelihoodLabel
            )
        }
        return (trimmed, prefix, Array(notListed), beyond)
    }

    /// The hops every path starts with, by component name.
    ///
    /// It stops one hop short of the shortest path: a path trimmed to nothing
    /// is no longer a story.
    private static func sharedPrefix(of paths: [ReportAttackPath]) -> [ReportAttackPathHop] {
        guard let shortest = paths.map(\.hops.count).min(), shortest > 1 else { return [] }

        var length = 0
        while length < shortest - 1 {
            let name = paths[0].hops[length].componentName
            guard paths.allSatisfy({ $0.hops[length].componentName == name }) else { break }
            length += 1
        }
        return Array(paths[0].hops.prefix(length))
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
