/// How much the answered controls take off a threat's score.
///
/// Spec section 3.1. The stage sits after the zone multiplier and before the
/// pathway mitigation, so a user who answers the questions sees the number
/// move, and nobody has to restate an implemented control as compensating
/// prose to make the number honest.
public enum ControlCoverage {
    /// The most the controls take off, whatever the coverage. A threat that
    /// every control answers is smaller, never absent.
    public static let maxReduction = 0.70

    /// The share of the applicable controls a person has implemented.
    ///
    /// `not_applicable` leaves the denominator, because a control that does
    /// not apply is not work anybody skipped. `accepted` stays in the
    /// denominator and gives nothing, because an accepted risk is still a
    /// risk.
    public static func coverage(of controls: [ResolvedControl]) -> Double {
        let applicable = controls.filter { $0.status != .notApplicable }
        guard applicable.isEmpty == false else { return 0 }
        let implemented = applicable.filter { $0.status == .implemented }
        return Double(implemented.count) / Double(applicable.count)
    }

    /// The score after the controls, and never below 1.
    public static func apply(to score: Int, controls: [ResolvedControl]) -> Int {
        let reduction = coverage(of: controls) * maxReduction
        return max(1, Int((Double(score) * (1 - reduction)).rounded()))
    }
}
