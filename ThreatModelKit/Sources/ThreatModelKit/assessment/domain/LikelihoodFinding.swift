/// What a person found out about how often an attack of this kind happens.
///
/// It is evidence, not a control. It multiplies the score, and it carries the
/// reasoning and the sources a reviewer reads.
public struct LikelihoodFinding: Equatable, Sendable {
    public let label: String
    public let likelihood: Likelihood
    public let rationale: String
    /// A URL, a CVE identifier, or any other text that says where the finding
    /// comes from.
    public let sources: [String]

    public init(label: String, likelihood: Likelihood, rationale: String, sources: [String] = []) {
        self.label = label
        self.likelihood = likelihood
        self.rationale = rationale
        self.sources = sources
    }
}
