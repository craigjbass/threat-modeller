/// What a threat harms.
///
/// A team that must answer "what threatens availability" reads this rather
/// than every threat. It labels a threat and moves no number.
public enum ThreatImpact: String, CaseIterable, Equatable, Sendable {
    case confidentiality
    case integrity
    case availability

    public var label: String {
        switch self {
        case .confidentiality: "Confidentiality"
        case .integrity: "Integrity"
        case .availability: "Availability"
        }
    }

    /// What the STRIDE categories say a threat harms, when the threat states
    /// nothing itself.
    ///
    /// | STRIDE | Harms |
    /// | --- | --- |
    /// | spoofing, information disclosure | confidentiality |
    /// | tampering, repudiation | integrity |
    /// | denial of service | availability |
    /// | elevation of privilege | all three |
    ///
    /// A threat that states no STRIDE category at all harms all three: a
    /// threat nobody has classified is not a threat to nothing.
    public static func derived(from stride: [StrideId]) -> [ThreatImpact] {
        guard stride.isEmpty == false else { return allCases }

        var found: [ThreatImpact] = []
        for category in stride {
            for impact in Self.byStride[category.value] ?? [] where found.contains(impact) == false {
                found.append(impact)
            }
        }
        // A category the table does not name says nothing about what the
        // threat harms, so a threat of only such categories harms all three
        // rather than nothing.
        return found.isEmpty ? allCases : allCases.filter(found.contains)
    }

    private static let byStride: [String: [ThreatImpact]] = [
        "spoofing": [.confidentiality],
        "information-disclosure": [.confidentiality],
        "information_disclosure": [.confidentiality],
        "tampering": [.integrity],
        "repudiation": [.integrity],
        "denial-of-service": [.availability],
        "denial_of_service": [.availability],
        "elevation-of-privilege": allCases,
        "elevation_of_privilege": allCases
    ]
}
