/// The rules a project enforces for itself.
///
/// A fixed set of named rules, not an expression language: a rule a team
/// cannot mistype, that the report can explain, and that survives a change to
/// the value tree.
public struct PolicySource: Equatable, Sendable {
    /// No threat at this level or worse is unanswered. Nil when the rule is
    /// not in force.
    public let maxOpenAtLevel: RiskLevel?
    /// Every accepted risk names an owner.
    public let acceptedRequiresOwner: Bool
    /// Every accepted risk names a review date.
    public let acceptedRequiresReviewBy: Bool
    /// Every implemented control on a threat at this level or worse, before
    /// its controls, states an evidence tier.
    public let implementedRequiresEvidenceAbove: RiskLevel?
    /// No component holding restricted data sits in a public zone or outside
    /// every zone.
    public let restrictedDataStaysOutOfPublicZones: Bool
    /// Every assumption names an owner.
    public let assumptionsRequireOwner: Bool
    /// The `.arch` file states `owner`.
    public let systemRequiresOwner: Bool
    /// The report template this project renders through, as a path from the
    /// project root. Nil renders through the shape this application ships.
    public let template: String?

    public init(
        maxOpenAtLevel: RiskLevel? = nil,
        acceptedRequiresOwner: Bool = false,
        acceptedRequiresReviewBy: Bool = false,
        implementedRequiresEvidenceAbove: RiskLevel? = nil,
        restrictedDataStaysOutOfPublicZones: Bool = false,
        assumptionsRequireOwner: Bool = false,
        systemRequiresOwner: Bool = false,
        template: String? = nil
    ) {
        self.template = template
        self.maxOpenAtLevel = maxOpenAtLevel
        self.acceptedRequiresOwner = acceptedRequiresOwner
        self.acceptedRequiresReviewBy = acceptedRequiresReviewBy
        self.implementedRequiresEvidenceAbove = implementedRequiresEvidenceAbove
        self.restrictedDataStaysOutOfPublicZones = restrictedDataStaysOutOfPublicZones
        self.assumptionsRequireOwner = assumptionsRequireOwner
        self.systemRequiresOwner = systemRequiresOwner
    }

    /// What a policy file holds beside its rules.
    public static let settingNames = ["template"]

    /// The names a policy file holds, in the order the design lists them.
    public static let ruleNames = [
        "max_open_at_level",
        "accepted_requires_owner",
        "accepted_requires_review_by",
        "implemented_requires_evidence_above",
        "restricted_data_stays_out_of_public_zones",
        "assumptions_require_owner",
        "system_requires_owner"
    ]

    /// What each rule asks, for the report.
    public static func asks(_ rule: String, value: String) -> String {
        switch rule {
        case "max_open_at_level": "no threat at \(value) or worse is unanswered"
        case "accepted_requires_owner": "every accepted risk names an owner"
        case "accepted_requires_review_by": "every accepted risk names a review date"
        case "implemented_requires_evidence_above":
            "every implemented control at \(value) or worse states evidence"
        case "restricted_data_stays_out_of_public_zones":
            "no restricted data sits in a public zone"
        case "assumptions_require_owner": "every assumption names an owner"
        case "system_requires_owner": "the file states an owner"
        default: rule
        }
    }

    /// The rules in force, as the report lists them: the name and what it
    /// asks, in the order the design lists them.
    public var inForce: [(name: String, asks: String)] {
        var rules: [(name: String, asks: String)] = []
        if let maxOpenAtLevel {
            rules.append(
                ("max_open_at_level", Self.asks("max_open_at_level", value: maxOpenAtLevel.rawValue))
            )
        }
        if acceptedRequiresOwner {
            rules.append(("accepted_requires_owner", Self.asks("accepted_requires_owner", value: "")))
        }
        if acceptedRequiresReviewBy {
            rules.append(
                ("accepted_requires_review_by", Self.asks("accepted_requires_review_by", value: ""))
            )
        }
        if let implementedRequiresEvidenceAbove {
            rules.append(
                (
                    "implemented_requires_evidence_above",
                    Self.asks(
                        "implemented_requires_evidence_above",
                        value: implementedRequiresEvidenceAbove.rawValue
                    )
                )
            )
        }
        if restrictedDataStaysOutOfPublicZones {
            rules.append(
                (
                    "restricted_data_stays_out_of_public_zones",
                    Self.asks("restricted_data_stays_out_of_public_zones", value: "")
                )
            )
        }
        if assumptionsRequireOwner {
            rules.append(
                ("assumptions_require_owner", Self.asks("assumptions_require_owner", value: ""))
            )
        }
        if systemRequiresOwner {
            rules.append(("system_requires_owner", Self.asks("system_requires_owner", value: "")))
        }
        return rules
    }

    public var isEmpty: Bool { inForce.isEmpty }
}

public struct PolicyRead: Equatable, Sendable {
    public let source: PolicySource?
    public let diagnostics: [Diagnostic]

    public init(source: PolicySource?, diagnostics: [Diagnostic]) {
        self.source = source
        self.diagnostics = diagnostics
    }

    public var hasErrors: Bool {
        diagnostics.contains { $0.severity == .error }
    }
}
