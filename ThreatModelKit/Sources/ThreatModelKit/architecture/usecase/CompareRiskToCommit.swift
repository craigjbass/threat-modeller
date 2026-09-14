import Foundation

public protocol CompareRiskToCommitUseCase {
    func execute(_ request: CompareRiskToCommitRequest) -> CompareRiskToCommitResponse
}

public struct CompareRiskToCommitRequest: Equatable, Sendable {
    /// What the model raises today, from the working tree.
    public let now: [ComparedThreat]
    /// What it raised at the commit compared against.
    public let then: [ComparedThreat]
    /// The catalogue tag each side named.
    public let catalogueNow: String?
    public let catalogueThen: String?

    public init(
        now: [ComparedThreat],
        then: [ComparedThreat],
        catalogueNow: String? = nil,
        catalogueThen: String? = nil
    ) {
        self.now = now
        self.then = then
        self.catalogueNow = catalogueNow
        self.catalogueThen = catalogueThen
    }
}

/// One threat, as the comparison reads it.
public struct ComparedThreat: Equatable, Sendable {
    public let key: ThreatKey
    public let name: String
    public let sourceName: String
    public let riskScore: Int
    /// The status of each control, by description.
    public let controlStatuses: [String: String]
    /// The controls this threat's answer accepts.
    public let acceptedControls: [String]
    /// The review date of each accepted control, by description.
    public let reviewDates: [String: String]

    public init(
        key: ThreatKey,
        name: String,
        sourceName: String,
        riskScore: Int,
        controlStatuses: [String: String] = [:],
        acceptedControls: [String] = [],
        reviewDates: [String: String] = [:]
    ) {
        self.key = key
        self.name = name
        self.sourceName = sourceName
        self.riskScore = riskScore
        self.controlStatuses = controlStatuses
        self.acceptedControls = acceptedControls
        self.reviewDates = reviewDates
    }
}

/// What changed between one commit and the working tree.
public struct RiskChange: Equatable, Sendable {
    /// Threats the working tree raises and the commit did not.
    public let raised: [String]
    /// Threats the commit raised and the working tree does not.
    public let gone: [String]
    /// One line per control whose status moved.
    public let controlsChanged: [String]
    /// Accepted risks added, and accepted risks whose review date moved.
    public let acceptedAdded: [String]
    public let reviewDatesMoved: [String]
    /// The score delta per element, worst first. Only elements that moved.
    public let scoreDeltas: [ElementDelta]
    /// The two catalogue tags, when they differ. A score that moved on a
    /// catalogue change is not a posture change.
    public let catalogueMoved: String?
    /// The total score now, then, and the difference.
    public let totalNow: Int
    public let totalThen: Int

    public init(
        raised: [String] = [],
        gone: [String] = [],
        controlsChanged: [String] = [],
        acceptedAdded: [String] = [],
        reviewDatesMoved: [String] = [],
        scoreDeltas: [ElementDelta] = [],
        catalogueMoved: String? = nil,
        totalNow: Int = 0,
        totalThen: Int = 0
    ) {
        self.raised = raised
        self.gone = gone
        self.controlsChanged = controlsChanged
        self.acceptedAdded = acceptedAdded
        self.reviewDatesMoved = reviewDatesMoved
        self.scoreDeltas = scoreDeltas
        self.catalogueMoved = catalogueMoved
        self.totalNow = totalNow
        self.totalThen = totalThen
    }

    public var delta: Int { totalNow - totalThen }

    public var isEmpty: Bool {
        raised.isEmpty && gone.isEmpty && controlsChanged.isEmpty
            && acceptedAdded.isEmpty && reviewDatesMoved.isEmpty
            && scoreDeltas.isEmpty && catalogueMoved == nil
    }

    /// What the executive summary states in one sentence.
    public var direction: String {
        switch delta {
        case 0: "Risk is unchanged since the previous assessment."
        case ..<0: "Risk is down \(-delta) since the previous assessment."
        default: "Risk is up \(delta) since the previous assessment."
        }
    }
}

/// One element whose score moved.
public struct ElementDelta: Equatable, Sendable {
    public let name: String
    public let now: Int
    public let then: Int

    public init(name: String, now: Int, then: Int) {
        self.name = name
        self.now = now
        self.then = then
    }

    public var delta: Int { now - then }
}

public enum CompareRiskToCommitResponse: Equatable, Sendable {
    case compared(RiskChange)
}

/// States what changed between a commit and the working tree.
///
/// It compares two readings of the same shape and holds no gateway, so the
/// history, the report and a test all feed it the same way.
public struct CompareRiskToCommit: CompareRiskToCommitUseCase {
    public init() {}

    public func execute(_ request: CompareRiskToCommitRequest) -> CompareRiskToCommitResponse {
        let nowByKey = Dictionary(
            request.now.map { ($0.key.value, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        let thenByKey = Dictionary(
            request.then.map { ($0.key.value, $0) },
            uniquingKeysWith: { first, _ in first }
        )

        let raised = request.now
            .filter { thenByKey[$0.key.value] == nil }
            .map { "\($0.name) on \($0.sourceName)" }
            .sorted()
        let gone = request.then
            .filter { nowByKey[$0.key.value] == nil }
            .map { "\($0.name) on \($0.sourceName)" }
            .sorted()

        var controlsChanged: [String] = []
        var acceptedAdded: [String] = []
        var reviewDatesMoved: [String] = []

        for threat in request.now {
            guard let before = thenByKey[threat.key.value] else { continue }

            for (control, status) in threat.controlStatuses.sorted(by: { $0.key < $1.key }) {
                let was = before.controlStatuses[control]
                guard let was, was != status else { continue }
                controlsChanged.append(
                    "\(threat.name) on \(threat.sourceName): \"\(control)\" \(was) \u{2192} \(status)"
                )
            }

            for control in threat.acceptedControls.sorted()
            where before.acceptedControls.contains(control) == false {
                acceptedAdded.append("\(threat.name) on \(threat.sourceName): \"\(control)\"")
            }

            for (control, date) in threat.reviewDates.sorted(by: { $0.key < $1.key }) {
                guard let was = before.reviewDates[control], was != date else { continue }
                reviewDatesMoved.append(
                    "\(threat.name) on \(threat.sourceName): \"\(control)\" \(was) \u{2192} \(date)"
                )
            }
        }

        // The score of each element, both sides, so a reader sees where the
        // movement is rather than only that the total moved.
        var nowByElement: [String: Int] = [:]
        var thenByElement: [String: Int] = [:]
        for threat in request.now { nowByElement[threat.sourceName, default: 0] += threat.riskScore }
        for threat in request.then { thenByElement[threat.sourceName, default: 0] += threat.riskScore }

        let deltas = Set(nowByElement.keys).union(thenByElement.keys)
            .map { name in
                ElementDelta(
                    name: name,
                    now: nowByElement[name] ?? 0,
                    then: thenByElement[name] ?? 0
                )
            }
            .filter { $0.delta != 0 }
            .sorted { left, right in
                if abs(left.delta) != abs(right.delta) { return abs(left.delta) > abs(right.delta) }
                return left.name < right.name
            }

        let catalogueMoved = request.catalogueNow != request.catalogueThen
            ? "the catalogue moved from \(request.catalogueThen ?? "no tag") "
                + "to \(request.catalogueNow ?? "no tag")"
            : nil

        return .compared(
            RiskChange(
                raised: raised,
                gone: gone,
                controlsChanged: controlsChanged,
                acceptedAdded: acceptedAdded,
                reviewDatesMoved: reviewDatesMoved,
                scoreDeltas: deltas,
                catalogueMoved: catalogueMoved,
                totalNow: request.now.reduce(0) { $0 + $1.riskScore },
                totalThen: request.then.reduce(0) { $0 + $1.riskScore }
            )
        )
    }
}
