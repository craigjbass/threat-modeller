/// The three tables a reader looks at before the threat list.
///
/// Spec section 10. A report of 147 threats with no rollup is a file nobody
/// reads to the end.
public enum ReportRollups {
    /// The top residual table holds this many rows.
    public static let topCount = 20

    public static func build(threats: [ReportThreat], zones: [ReportZone]) -> ReportRollupTables {
        ReportRollupTables(
            byZone: zones.map { zone in
                let held = Set(zone.componentIds.map { "component:\($0)" })
                let raised = threats.filter { held.contains($0.sourceId) }
                return ReportZoneRollup(
                    zoneName: zone.name,
                    componentCount: zone.componentNames.count,
                    byLevel: counts(of: raised.map(\.riskLevel)),
                    worstScore: raised.map(\.riskScore).max() ?? 0
                )
            },
            topResidual: Array(
                threats.sorted { left, right in
                    if left.riskScore != right.riskScore { return left.riskScore > right.riskScore }
                    return left.name < right.name
                }.prefix(topCount)
            ),
            bySourceKind: ["Component", "Connection", "Zone"].compactMap { kind in
                let count = threats.filter { $0.sourceKind == kind }.count
                return count > 0 ? ReportCount(label: kind, count: count) : nil
            }
        )
    }

    /// Worst level first, which is the order the risk ladder runs in.
    private static func counts(of levels: [String]) -> [ReportCount] {
        var held: [String: Int] = [:]
        for level in levels { held[level, default: 0] += 1 }
        return ["critical", "high", "medium", "low"].compactMap { level in
            held[level].map { ReportCount(label: level, count: $0) }
        }
    }
}
