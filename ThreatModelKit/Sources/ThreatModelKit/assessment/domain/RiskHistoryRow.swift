import Foundation

/// What one sampled commit scored.
///
/// A commit whose files do not parse keeps its row and states so: a zero would
/// read as "no risk", which is the opposite of what a file that does not parse
/// means.
public struct RiskHistoryRow: Equatable, Sendable {
    public let commit: SourceCommit
    /// The numbers, or nil when the files at that commit did not parse.
    public let numbers: RiskHistoryNumbers?

    public init(commit: SourceCommit, numbers: RiskHistoryNumbers?) {
        self.commit = commit
        self.numbers = numbers
    }

    public var didParse: Bool { numbers != nil }
}

/// The numbers that describe one commit's posture.
public struct RiskHistoryNumbers: Equatable, Sendable {
    /// The sum of every residual score: the one number a direction is read
    /// from.
    public let totalScore: Int
    /// How many threats sit at each risk level, worst level first.
    public let byLevel: [String: Int]
    /// The worst single threat, which a total can hide.
    public let worstScore: Int
    public let threatCount: Int
    /// How many risks the organisation carries.
    public let acceptedRisks: Int
    /// How many written routes are still open.
    public let openAttackTrees: Int
    /// The catalogue version that produced these numbers.
    public let catalogueTag: String?

    public init(
        totalScore: Int,
        byLevel: [String: Int] = [:],
        worstScore: Int = 0,
        threatCount: Int = 0,
        acceptedRisks: Int = 0,
        openAttackTrees: Int = 0,
        catalogueTag: String? = nil
    ) {
        self.totalScore = totalScore
        self.byLevel = byLevel
        self.worstScore = worstScore
        self.threatCount = threatCount
        self.acceptedRisks = acceptedRisks
        self.openAttackTrees = openAttackTrees
        self.catalogueTag = catalogueTag
    }
}
