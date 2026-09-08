/// Which connection threats a TLS-enforcing endpoint mitigates.
///
/// WARNING: the flag is for display only. It never changes a risk score.
/// Spec section 5.3 states that rule; the original application behaves the
/// same way, and the ported tests hold it.
public enum ConnectionEncryption {
    /// Only these two threats carry the flag. Every other connection threat is
    /// unaffected by transport encryption.
    public static let mitigatedThreatIds: Set<ThreatId> = [
        ThreatId("connection-mitm"),
        ThreatId("connection-data-exposure")
    ]

    /// True when the threat is one of the two, and either endpoint technology
    /// enforces encryption. A technology the catalogue no longer holds counts
    /// as not enforcing it.
    public static func isTlsMitigated(
        threat: Threat,
        source: Technology?,
        target: Technology?
    ) -> Bool {
        guard mitigatedThreatIds.contains(threat.id) else { return false }
        return source?.enforcesEncryption == true || target?.enforcesEncryption == true
    }
}
