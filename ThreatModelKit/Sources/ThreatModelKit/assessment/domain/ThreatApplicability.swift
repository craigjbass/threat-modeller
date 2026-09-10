/// Whether a threat is raised at all.
///
/// Task 8 fills these in. Until then every threat is raised, which is what the
/// resolver does today.
public enum ThreatApplicability {
    public static func appliesToComponent(threat: Threat, runsAs: PrivilegeLevel) -> Bool {
        true
    }

    public static func appliesToConnection(
        threat: Threat,
        kind: FlowKind,
        crossesPrivilege: Bool
    ) -> Bool {
        true
    }

    public static func appliesToZone(threat: Threat, boundary: ZoneBoundary) -> Bool {
        true
    }
}
