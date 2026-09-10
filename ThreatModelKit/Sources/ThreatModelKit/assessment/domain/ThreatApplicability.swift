/// Whether a threat is raised at all.
///
/// Spec sections 4.3, 5.1 and 5.2. The rules keep the vendored catalogue
/// correct without editing it: a threat that states no kind and no boundary
/// means what it meant before this application knew about kinds.
public enum ThreatApplicability {
    /// A component threat that names no level is raised at every level.
    public static func appliesToComponent(threat: Threat, runsAs: PrivilegeLevel) -> Bool {
        threat.appliesToPrivilegeLevels.isEmpty
            || threat.appliesToPrivilegeLevels.contains(runsAs)
    }

    /// A privilege threat is raised only where the flow crosses a level, and
    /// its kinds do not matter. Every other threat is raised on the kinds it
    /// names, and a threat that names none is a network threat.
    public static func appliesToConnection(
        threat: Threat,
        kind: FlowKind,
        crossesPrivilege: Bool
    ) -> Bool {
        if threat.boundary == .privilege { return crossesPrivilege }
        if threat.appliesToFlowKinds.isEmpty { return kind == .network }
        return threat.appliesToFlowKinds.contains(kind)
    }

    /// A zone raises the threats of its own boundary and no others. A threat
    /// that states no boundary is a network threat.
    public static func appliesToZone(threat: Threat, boundary: ZoneBoundary) -> Bool {
        (threat.boundary ?? .network) == boundary
    }
}
