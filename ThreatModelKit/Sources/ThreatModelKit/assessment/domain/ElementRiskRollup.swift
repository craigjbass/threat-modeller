/// What one element on the diagram carries, in the form the canvas paints.
/// One open threat on an element, for the text a reader sees on hover.
public struct OpenThreat: Equatable, Sendable {
    public let name: String
    public let score: Int

    public init(name: String, score: Int) {
        self.name = name
        self.score = score
    }
}

public struct ElementRisk: Equatable, Sendable {
    /// "component:<id>", "connection:<id>" or "zone:<id>".
    public let sourceId: String
    /// Threats on this element that no control answers.
    public let openCount: Int
    public let totalCount: Int
    /// The highest residual level on this element. `AssessedThreat.riskLevel`
    /// is already residual, so nothing here applies a control a second time.
    public let highestLevelId: String?
    /// The three worst open threats on this element, worst first. What a
    /// reader sees when they hover the element's badge.
    public let worstOpen: [OpenThreat]

    public init(
        sourceId: String,
        openCount: Int,
        totalCount: Int,
        highestLevelId: String?,
        worstOpen: [OpenThreat] = []
    ) {
        self.sourceId = sourceId
        self.openCount = openCount
        self.totalCount = totalCount
        self.highestLevelId = highestLevelId
        self.worstOpen = worstOpen
    }
}

/// Turns the assessed threats into one value for each element on the diagram.
///
/// The canvas needs a colour and a count for every node, every flow and every
/// zone. The rule that decides them lives here, so a test runs it without a
/// window.
public enum ElementRiskRollup {
    /// A threat is answered when one control is implemented, or when every
    /// control it has is set aside. A threat with no control at all is open.
    public static func isOpen(_ threat: AssessedThreat) -> Bool {
        if threat.controls.isEmpty { return true }

        let statuses = threat.controls.map { ControlStatus(rawValue: $0.statusId) ?? .notImplemented }
        if statuses.contains(.implemented) { return false }
        return statuses.contains(.notImplemented)
    }

    /// `levelOrder` runs weakest first, as the taxonomy states the severities.
    /// A level the order does not name sorts below every level it does name,
    /// and the rollup still reports it rather than dropping it.
    public static func byElement(
        _ threats: [AssessedThreat],
        levelOrder: [String]
    ) -> [String: ElementRisk] {
        func rank(_ levelId: String) -> Int {
            levelOrder.firstIndex(of: levelId) ?? -1
        }

        var built: [String: ElementRisk] = [:]
        var openByElement: [String: [OpenThreat]] = [:]

        for threat in threats where isOpen(threat) {
            openByElement[threat.source.id, default: []].append(
                OpenThreat(name: threat.name, score: threat.riskScore)
            )
        }
        // Worst first, and a tie reads in the order the list holds it, so the
        // text a reader sees is the order they see on the cards.
        for id in openByElement.keys {
            openByElement[id] = openByElement[id]?
                .enumerated()
                .sorted { ($0.element.score, -$0.offset) > ($1.element.score, -$1.offset) }
                .map(\.element)
        }

        for threat in threats {
            let sourceId = threat.source.id
            let held = built[sourceId]
            let highest: String?

            if let current = held?.highestLevelId, rank(current) >= rank(threat.riskLevel) {
                highest = current
            } else {
                highest = threat.riskLevel
            }

            built[sourceId] = ElementRisk(
                sourceId: sourceId,
                openCount: (held?.openCount ?? 0) + (isOpen(threat) ? 1 : 0),
                totalCount: (held?.totalCount ?? 0) + 1,
                highestLevelId: highest,
                worstOpen: Array((openByElement[sourceId] ?? []).prefix(3))
            )
        }

        return built
    }
}
