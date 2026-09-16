/// The likelihood a threat was scored with, and where it came from.
///
/// A reader who sees a score fall has to see why, so the tier and the reason
/// travel together.
public enum LikelihoodSource: Equatable, Sendable {
    case catalogue(Likelihood)
    case actor(Likelihood, actorId: ThreatActorId, actorName: String)
    /// A known exploited CVE on the component the threat is raised on.
    case vulnerability(Likelihood, cveId: String)
    case finding(LikelihoodFinding)

    public var likelihood: Likelihood {
        switch self {
        case .catalogue(let likelihood): likelihood
        case .actor(let likelihood, _, _): likelihood
        case .vulnerability(let likelihood, _): likelihood
        case .finding(let finding): finding.likelihood
        }
    }

    /// What a vulnerability reason ends with, so a writer that holds only the
    /// text tells it from an actor's.
    public static let knownExploitedSuffix = ", known exploited"

    /// What the report and the threat card write after the tier.
    public var reason: String {
        switch self {
        case .catalogue: "from the catalogue"
        case .actor(_, _, let actorName): "set by \(actorName)"
        case .vulnerability(_, let cveId): "set by \(cveId)\(Self.knownExploitedSuffix)"
        case .finding(let finding): finding.label
        }
    }
}
