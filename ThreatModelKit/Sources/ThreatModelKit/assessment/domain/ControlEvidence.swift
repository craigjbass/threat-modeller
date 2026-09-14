/// What proves a control is in place.
///
/// Four teams write `implemented` and mean four things: somebody believes the
/// control is on; a policy says it is on; somebody read the configuration; a
/// test fails when it is off. The tier says which, and a reader can check the
/// stronger ones for themselves.
///
/// WARNING: a tier moves no score. A score that moved with the tier would fall
/// when a team wrote down what it already knew, and rise when a document went
/// stale. The control is either in place or it is not; the tier says how well
/// a reader can check that claim.
public enum ControlEvidence: String, CaseIterable, Equatable, Sendable, Comparable {
    /// Somebody says the control is in place. A reader can ask them.
    case asserted
    /// A written policy or procedure states it.
    case documented
    /// Somebody read the running configuration.
    case configured
    /// A test runs and fails when the control is off.
    case tested
    /// An independent audit found the control in place.
    case audited

    /// Weakest first, which is the order of what a reader can check.
    public var rank: Int {
        switch self {
        case .asserted: 1
        case .documented: 2
        case .configured: 3
        case .tested: 4
        case .audited: 5
        }
    }

    public var label: String {
        rawValue
    }

    public static func < (left: ControlEvidence, right: ControlEvidence) -> Bool {
        left.rank < right.rank
    }

    /// What the parser says about a word that is no tier.
    public static var wordsItHolds: String {
        allCases.map { "\"\($0.rawValue)\"" }.joined(separator: ", ")
    }
}

/// The tier, where the proof is and when somebody last checked.
///
/// Nil throughout for a control that states none of the three, which is every
/// control in every file written before this existed.
public struct ControlProof: Equatable, Sendable {
    public let evidence: ControlEvidence?
    /// Where the proof is: a URL, a document number, a test name.
    public let reference: String
    public let verifiedOn: GovernanceDate?

    public init(
        evidence: ControlEvidence? = nil,
        reference: String = "",
        verifiedOn: GovernanceDate? = nil
    ) {
        self.evidence = evidence
        self.reference = reference
        self.verifiedOn = verifiedOn
    }

    public var isEmpty: Bool {
        evidence == nil && reference.isEmpty && verifiedOn == nil
    }

    /// What the report writes after an implemented control: the tier, the
    /// reference and the date, or `no evidence`.
    public var says: String {
        guard let evidence else { return "no evidence" }
        var parts = [evidence.label]
        if reference.isEmpty == false { parts.append(reference) }
        if let verifiedOn { parts.append("verified \(verifiedOn)") }
        return parts.joined(separator: ", ")
    }
}
