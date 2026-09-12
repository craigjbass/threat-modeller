/// What one element on the diagram carries, in the form the canvas paints.
public struct ElementRisk: Equatable, Sendable {
    /// "component:<id>", "connection:<id>" or "zone:<id>".
    public let sourceId: String
    /// Threats on this element that no control answers.
    public let openCount: Int
    public let totalCount: Int
    /// The highest residual level on this element. `AssessedThreat.riskLevel`
    /// is already residual, so nothing here applies a control a second time.
    public let highestLevelId: String?

    public init(sourceId: String, openCount: Int, totalCount: Int, highestLevelId: String?) {
        self.sourceId = sourceId
        self.openCount = openCount
        self.totalCount = totalCount
        self.highestLevelId = highestLevelId
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
                highestLevelId: highest
            )
        }

        return built
    }
}
