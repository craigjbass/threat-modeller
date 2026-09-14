/// A risk the organisation decided to carry, and who decided it.
///
/// Accepting a risk lowers no score. It records the decision: who carries it,
/// when they took it and when they read it again.
public struct RiskAcceptance: Equatable, Sendable {
    /// The control's description, which is its identity in every file.
    public let control: String
    public let owner: String
    public let acceptedOn: GovernanceDate?
    public let reviewBy: GovernanceDate?
    public let rationale: String
    public let sources: [String]

    public init(
        control: String,
        owner: String = "",
        acceptedOn: GovernanceDate? = nil,
        reviewBy: GovernanceDate? = nil,
        rationale: String = "",
        sources: [String] = []
    ) {
        self.control = control
        self.owner = owner
        self.acceptedOn = acceptedOn
        self.reviewBy = reviewBy
        self.rationale = rationale
        self.sources = sources
    }

    /// True when the review date has passed. A risk nobody has read again is
    /// a decision nobody has checked.
    public func isOverdue(on today: GovernanceDate) -> Bool {
        guard let reviewBy else { return false }
        return reviewBy < today
    }
}
