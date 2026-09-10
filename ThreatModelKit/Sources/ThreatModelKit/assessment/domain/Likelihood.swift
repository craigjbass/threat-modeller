/// How often an attack of this kind actually happens.
///
/// The score says how bad a threat is. This says whether anybody does it. A
/// threat that states none is `commodity`, so a model that says nothing about
/// likelihood keeps the numbers it had.
public struct Likelihood: Equatable, Sendable {
    public let id: String
    public let label: String
    /// 0.0 to 1.0. The stage multiplies the score by this.
    public let factor: Double

    private init(id: String, label: String, factor: Double) {
        self.id = id
        self.label = label
        self.factor = factor
    }

    /// Malware families use it today.
    public static let commodity = Likelihood(id: "commodity", label: "Commodity", factor: 1.0)
    /// A funded attacker uses it against a chosen target.
    public static let targeted = Likelihood(id: "targeted", label: "Targeted", factor: 0.6)
    /// A researcher has shown it, and no campaign has used it.
    public static let research = Likelihood(id: "research", label: "Research", factor: 0.25)

    public static let allTiers: [Likelihood] = [.commodity, .targeted, .research]

    /// The tier with that id, or nil. A file that names another word is wrong,
    /// and the parser says so.
    public init?(rawValue: String) {
        guard let tier = Self.allTiers.first(where: { $0.id == rawValue }) else { return nil }
        self = tier
    }

    /// A number from 0 to 100, which is a percentage.
    public init?(prior: Int) {
        guard (0...100).contains(prior) else { return nil }
        self = Likelihood(id: String(prior), label: "\(prior)%", factor: Double(prior) / 100)
    }

    /// The score after the likelihood, and never below 1.
    public static func apply(to score: Int, likelihood: Likelihood) -> Int {
        max(1, Int((Double(score) * likelihood.factor).rounded()))
    }
}
