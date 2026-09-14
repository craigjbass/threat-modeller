/// Evaluates the rules a project states for itself.
///
/// One body per rule, over plain inputs, so the check and the report can never
/// disagree about whether a rule holds: `CheckPolicy` builds the inputs from
/// the files, and `BuildThreatModelReport` builds them from the model.
public enum PolicyRules {
    /// One threat, as a rule reads it.
    public struct Threat: Equatable, Sendable {
        public let key: ThreatKey
        public let threatId: String
        public let sourceKind: String
        public let sourceId: String
        public let riskLevel: RiskLevel
        /// The level before the controls lowered the score.
        public let levelBeforeControls: RiskLevel
        public let isAnswered: Bool
        /// The implemented controls that state no evidence tier.
        public let unevidencedControls: [String]
        /// The accepted controls, by description.
        public let acceptedControls: [String]

        public init(
            key: ThreatKey,
            threatId: String,
            sourceKind: String,
            sourceId: String,
            riskLevel: RiskLevel,
            levelBeforeControls: RiskLevel,
            isAnswered: Bool,
            unevidencedControls: [String] = [],
            acceptedControls: [String] = []
        ) {
            self.key = key
            self.threatId = threatId
            self.sourceKind = sourceKind
            self.sourceId = sourceId
            self.riskLevel = riskLevel
            self.levelBeforeControls = levelBeforeControls
            self.isAnswered = isAnswered
            self.unevidencedControls = unevidencedControls
            self.acceptedControls = acceptedControls
        }
    }

    /// One component, as the zone rule reads it.
    public struct Element: Equatable, Sendable {
        public let id: String
        public let sensitivity: DataSensitivity
        /// The zone it sits in, or nil when it sits outside every zone.
        public let zone: NetworkZone?

        public init(id: String, sensitivity: DataSensitivity, zone: NetworkZone?) {
            self.id = id
            self.sensitivity = sensitivity
            self.zone = zone
        }
    }

    /// Everything the rules read.
    public struct Reading: Equatable, Sendable {
        public let threats: [Threat]
        public let elements: [Element]
        /// The accepted risks the governance file states, by threat key.
        public let acceptedRisks: [ThreatKey: [RiskAcceptance]]
        /// The assumptions, by label, and who owns each.
        public let assumptions: [(label: String, owner: String)]
        public let systemOwner: String

        public init(
            threats: [Threat] = [],
            elements: [Element] = [],
            acceptedRisks: [ThreatKey: [RiskAcceptance]] = [:],
            assumptions: [(label: String, owner: String)] = [],
            systemOwner: String = ""
        ) {
            self.threats = threats
            self.elements = elements
            self.acceptedRisks = acceptedRisks
            self.assumptions = assumptions
            self.systemOwner = systemOwner
        }

        public static func == (left: Reading, right: Reading) -> Bool {
            left.threats == right.threats
                && left.elements == right.elements
                && left.acceptedRisks == right.acceptedRisks
                && left.assumptions.map(\.label) == right.assumptions.map(\.label)
                && left.assumptions.map(\.owner) == right.assumptions.map(\.owner)
                && left.systemOwner == right.systemOwner
        }
    }

    /// Every rule in force, and what breached it.
    public static func evaluate(_ policy: PolicySource, reading: Reading) -> [PolicyRuleResult] {
        var rules: [PolicyRuleResult] = []

        if let level = policy.maxOpenAtLevel {
            rules.append(
                result(
                    "max_open_at_level",
                    value: level.rawValue,
                    breaches: reading.threats
                        .filter { $0.riskLevel.rank >= level.rank && $0.isAnswered == false }
                        .map {
                            "\($0.threatId) on \($0.sourceKind) \"\($0.sourceId)\" "
                                + "(\($0.riskLevel.label)) is open at or above \(level.rawValue)"
                        }
                )
            )
        }

        if policy.acceptedRequiresOwner {
            rules.append(
                result(
                    "accepted_requires_owner",
                    breaches: accepted(reading) { risk in (risk?.owner ?? "").isEmpty }
                        .map { "\($0) is accepted by nobody" }
                )
            )
        }

        if policy.acceptedRequiresReviewBy {
            rules.append(
                result(
                    "accepted_requires_review_by",
                    breaches: accepted(reading) { $0?.reviewBy == nil }
                        .map { "\($0) is accepted with no review date" }
                )
            )
        }

        if let level = policy.implementedRequiresEvidenceAbove {
            var breaches: [String] = []
            for threat in reading.threats where threat.levelBeforeControls.rank >= level.rank {
                for control in threat.unevidencedControls {
                    breaches.append(
                        "\(threat.key.value): \"\(control)\" is implemented above "
                            + "\(level.rawValue) risk with no evidence"
                    )
                }
            }
            rules.append(
                result("implemented_requires_evidence_above", value: level.rawValue, breaches: breaches)
            )
        }

        if policy.restrictedDataStaysOutOfPublicZones {
            rules.append(
                result(
                    "restricted_data_stays_out_of_public_zones",
                    breaches: reading.elements
                        .filter { $0.sensitivity == .restricted && $0.zone != .privateZone }
                        .map { element in
                            element.zone == nil
                                ? "\"\(element.id)\" holds restricted data outside every zone"
                                : "\"\(element.id)\" holds restricted data in a public zone"
                        }
                )
            )
        }

        if policy.assumptionsRequireOwner {
            rules.append(
                result(
                    "assumptions_require_owner",
                    breaches: reading.assumptions
                        .filter { $0.owner.isEmpty }
                        .map { "the assumption \"\($0.label)\" names no owner" }
                )
            )
        }

        if policy.systemRequiresOwner {
            rules.append(
                result(
                    "system_requires_owner",
                    breaches: reading.systemOwner.isEmpty ? ["this system states no owner"] : []
                )
            )
        }

        return rules
    }

    /// The keys of every accepted control whose governance stanza fails the
    /// question asked of it.
    private static func accepted(
        _ reading: Reading,
        fails: (RiskAcceptance?) -> Bool
    ) -> [String] {
        var keys: [String] = []
        for threat in reading.threats {
            for control in threat.acceptedControls {
                let stanza = reading.acceptedRisks[threat.key]?.first { $0.control == control }
                if fails(stanza) { keys.append(threat.key.value) }
            }
        }
        return keys
    }

    private static func result(
        _ name: String,
        value: String = "",
        breaches: [String]
    ) -> PolicyRuleResult {
        PolicyRuleResult(
            name: name,
            asks: PolicySource.asks(name, value: value),
            breaches: breaches
        )
    }
}
