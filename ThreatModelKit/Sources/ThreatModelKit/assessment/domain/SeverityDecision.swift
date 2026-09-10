/// The severity an assessor chose for one threat on one source, and why.
///
/// The `severity` attribute a controls file holds is what the compiler wrote,
/// and the application recomputes it. This is what a person decided, so a
/// catalogue that raises a threat's severity never hides behind a stale
/// written value.
public struct SeverityDecision: Equatable, Sendable {
    public let severityId: String
    public let rationale: String
    public let sources: [String]

    public init(severityId: String, rationale: String, sources: [String] = []) {
        self.severityId = severityId
        self.rationale = rationale
        self.sources = sources
    }
}
