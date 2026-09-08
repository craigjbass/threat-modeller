import Foundation

/// How much a zone reduces the risk of what it holds. Spec section 5.3.
public enum ZoneMultiplier {
    /// 1.0 outside every zone, 1.0 in a public zone, 1.0 in a private zone
    /// with risk reduction off, else `(100 − reductionPercent) / 100`.
    public static func value(for zone: Zone?) -> Double {
        guard let zone,
              zone.networkZone == .privateZone,
              zone.riskReductionEnabled else { return 1.0 }
        return Double(100 - zone.riskReductionPercent) / 100
    }

    /// The multiplier a link takes.
    ///
    /// A link takes one only when both ends sit in private zones, and then it
    /// takes the lower of the two reduction percentages — which is the higher
    /// of the two multipliers. An end with reduction off counts as no
    /// reduction, so the link takes none.
    public static func valueForConnection(sourceZone: Zone?, targetZone: Zone?) -> Double {
        guard let sourceZone, let targetZone,
              sourceZone.networkZone == .privateZone,
              targetZone.networkZone == .privateZone else { return 1.0 }
        return max(value(for: sourceZone), value(for: targetZone))
    }

    /// The score after the multiplier, rounded. Spec section 5.3.
    public static func apply(_ multiplier: Double, to score: Int) -> Int {
        Int((Double(score) * multiplier).rounded())
    }
}
