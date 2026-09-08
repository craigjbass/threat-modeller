/// Picks the sensitivity a threat is scored against when more than one
/// component supplies data.
///
/// Spec section 5.3: a connection's sensitivity is the higher of its two
/// endpoints' sensitivities. Milestone 5 adds the downstream rule for pathway
/// threats; do not add it before then.
public enum SensitivityLadder {
    public static func higher(_ first: DataSensitivity, _ second: DataSensitivity) -> DataSensitivity {
        first.rank >= second.rank ? first : second
    }

    /// The highest of many, or nil for none. A pathway threat escalates to the
    /// highest sensitivity among the components it directly feeds.
    public static func highest(of sensitivities: [DataSensitivity]) -> DataSensitivity? {
        sensitivities.max { $0.rank < $1.rank }
    }
}
