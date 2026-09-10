/// Traces every attack path from an entry point to the sensitive data it can
/// reach.
///
/// Task 15 fills this in.
public enum AttackPaths {
    public static func build(
        components: [Component],
        connections: [Connection],
        zones: [Zone],
        threats: [ReportThreat],
        nameOf: (ComponentId) -> String
    ) -> (paths: [ReportAttackPath], notListed: Int) {
        ([], 0)
    }
}
