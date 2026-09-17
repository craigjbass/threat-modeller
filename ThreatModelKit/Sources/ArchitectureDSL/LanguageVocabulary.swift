import ThreatModelKit

/// One block of one language, and the attribute names its parser reads.
///
/// The parsers used to spell their vocabulary twice: once as the `case` words
/// of a `switch`, and again as prose inside the unknown-attribute message. The
/// two copies drifted. Now the message is built from this declaration, so the
/// declaration is the vocabulary, and a test can walk it.
public struct LanguageBlock: Equatable, Sendable {
    /// The file the block lives in: `arch`, `controls`, `attacktree`,
    /// `governance`, `policy` or `lib`.
    public let language: String
    /// The name the parity list knows the block by. A keyword that names two
    /// different blocks carries a qualifier in brackets.
    public let name: String
    /// How the unknown-attribute message opens.
    public let phrase: String
    /// The attribute names the parser reads, in the order the message lists
    /// them.
    public let attributes: [String]
    /// True while the message separates every word with a comma. False puts
    /// `and` before the last word.
    public let listsWithCommasAlone: Bool

    public init(
        language: String,
        name: String,
        phrase: String,
        attributes: [String],
        listsWithCommasAlone: Bool = false
    ) {
        self.language = language
        self.name = name
        self.phrase = phrase
        self.attributes = attributes
        self.listsWithCommasAlone = listsWithCommasAlone
    }

    /// The message a parser records for a word this block does not hold.
    public func unknownAttribute(_ word: String) -> String {
        "\(phrase) \(sentence), not \"\(word)\""
    }

    /// The word list as the message reads it.
    public var sentence: String {
        guard listsWithCommasAlone == false else {
            return attributes.joined(separator: ", ")
        }
        guard let last = attributes.last else { return "" }
        guard attributes.count > 1 else { return last }
        return attributes.dropLast().joined(separator: ", ") + " and " + last
    }
}

/// Every block of every language, by id.
///
/// The case list is the walk a parity test takes: `LanguageBlockId.allCases`
/// gives every block, and `block.attributes` gives every attribute the window
/// has to write. A `switch` states the table, so the compiler refuses a new
/// case with no entry.
public enum LanguageBlockId: String, CaseIterable, Sendable {
    case archSystem
    case archUser
    case archAttribute
    case archAssumption
    case archDiagram
    case archThirdParty
    case archSystemAsset
    case archUseCase
    case archExclusion
    case archThreatActor
    case archTechnology
    case archZone
    case archComponent
    case archComponentAsset
    case archFlow
    case archMitigates
    case archRecommendation

    case controlsDocument
    case controlsTree
    case controlsSufficient
    case controlsStep
    case controlsThreat
    case controlsLikelihood
    case controlsSeverityOverride
    case controlsControl
    case controlsCompensating
    case controlsRecommendation

    case attackTreeDocument
    case attackTreeTree
    case attackTreeStep
    case attackTreeAllOf
    case attackTreeAnyOf
    case attackTreeThen

    case governanceDocument
    case governanceThreat
    case governanceAccepted
    case governanceWork

    case policyDocument

    case libraryLibrary
    case libraryClassification
    case libraryOverride
    case libraryCategory
    case librarySeverity
    case libraryStride
    case libraryTechnology
    case libraryThreat
    case libraryMitigation
    case libraryThreatActor
    case libraryMitre

    /// The message a parser records for a word this block does not hold.
    public func unknownAttribute(_ word: String) -> String {
        block.unknownAttribute(word)
    }

    public var block: LanguageBlock {
        switch self {
        case .archSystem:
            LanguageBlock(
                language: "arch",
                name: "system",
                phrase: "a system holds",
                attributes: [
                    "catalogue", "owner", "description", "authors", "links", "repositories",
                    "created", "reviewed", "version", "attribute", "technology", "zone",
                    "component", "user", "flow", "mitigates", "risk_tolerance",
                    "requires_evidence_above", "assumption", "use_case", "exclusion", "asset",
                    "third_party", "diagram", "faces", "threat_actor"
                ]
            )
        case .archUser:
            LanguageBlock(
                language: "arch",
                name: "user",
                phrase: "a user holds",
                attributes: ["name", "role", "access", "reaches", "threat_actor"]
            )
        case .archAttribute:
            LanguageBlock(
                language: "arch",
                name: "attribute",
                phrase: "an attribute holds",
                attributes: ["value"]
            )
        case .archAssumption:
            LanguageBlock(
                language: "arch",
                name: "assumption",
                phrase: "an assumption holds",
                attributes: ["text", "owner"]
            )
        case .archDiagram:
            LanguageBlock(
                language: "arch",
                name: "diagram",
                phrase: "a diagram holds",
                attributes: ["kind", "text"]
            )
        case .archThirdParty:
            LanguageBlock(
                language: "arch",
                name: "third_party",
                phrase: "a third_party holds",
                attributes: [
                    "name", "description", "kind", "paying_customer", "uptime", "uptime_notes",
                    "owner", "link"
                ]
            )
        case .archSystemAsset:
            LanguageBlock(
                language: "arch",
                name: "asset (in system)",
                phrase: "an asset holds",
                attributes: ["name", "classification", "description", "owner"]
            )
        case .archUseCase:
            LanguageBlock(
                language: "arch",
                name: "use_case",
                phrase: "a use_case holds",
                attributes: ["text"]
            )
        case .archExclusion:
            LanguageBlock(
                language: "arch",
                name: "exclusion",
                phrase: "an exclusion holds",
                attributes: ["text", "rationale"]
            )
        case .archThreatActor:
            LanguageBlock(
                language: "arch",
                name: "threat_actor",
                phrase: "a threat actor holds",
                attributes: [
                    "name", "description", "aliases", "capability", "intent", "performs",
                    "techniques", "performs_catalogue_tier"
                ]
            )
        case .archTechnology:
            LanguageBlock(
                language: "arch",
                name: "technology",
                phrase: "a technology holds",
                attributes: ["name", "category", "description", "threats", "encrypts", "control"]
            )
        case .archZone:
            LanguageBlock(
                language: "arch",
                name: "zone",
                phrase: "a zone holds",
                attributes: [
                    "kind", "network", "name", "reduces_risk", "reduces_risk_by", "component",
                    "boundary", "description", "source", "tags"
                ]
            )
        case .archComponent:
            LanguageBlock(
                language: "arch",
                name: "component",
                phrase: "a component holds",
                attributes: [
                    "technology", "name", "zone", "data", "status", "version", "cves", "holds",
                    "provided_by", "source", "threats", "runs_as", "shape", "tags", "asset"
                ]
            )
        case .archComponentAsset:
            LanguageBlock(
                language: "arch",
                name: "asset (in component)",
                phrase: "an asset holds",
                attributes: ["data"]
            )
        case .archFlow:
            LanguageBlock(
                language: "arch",
                name: "flow",
                phrase: "a flow holds",
                attributes: ["kind", "description", "carries", "tags"]
            )
        case .archMitigates:
            LanguageBlock(
                language: "arch",
                name: "mitigates",
                phrase: "a mitigates edge holds",
                attributes: ["threats", "reduces_risk_by", "status", "recommendation"]
            )
        case .archRecommendation:
            LanguageBlock(
                language: "arch",
                name: "recommendation (in mitigates)",
                phrase: "a recommendation holds",
                attributes: ["text", "note", "blocked_by", "sources"]
            )

        case .controlsDocument:
            LanguageBlock(
                language: "controls",
                name: "controls for",
                phrase: "a controls file holds",
                attributes: [
                    "catalogue", "tolerance", "threat", "tree", "stale threat", "stale tree"
                ]
            )
        case .controlsTree:
            LanguageBlock(
                language: "controls",
                name: "tree",
                phrase: "a tree holds",
                attributes: [
                    "goal", "chain", "raises_risk_by", "score", "score_before", "closed_by",
                    "sufficient", "step"
                ]
            )
        case .controlsSufficient:
            LanguageBlock(
                language: "controls",
                name: "sufficient",
                phrase: "a sufficient control holds",
                attributes: ["state"]
            )
        case .controlsStep:
            LanguageBlock(
                language: "controls",
                name: "step",
                phrase: "a step holds",
                attributes: ["state", "by", "position"]
            )
        case .controlsThreat:
            LanguageBlock(
                language: "controls",
                name: "threat",
                phrase: "a threat holds",
                attributes: [
                    "severity", "score", "impacts", "likelihood", "severity_override", "control",
                    "compensating", "recommendation"
                ]
            )
        case .controlsLikelihood:
            LanguageBlock(
                language: "controls",
                name: "likelihood",
                phrase: "a likelihood holds",
                attributes: ["tier", "prior", "rationale", "sources"]
            )
        case .controlsSeverityOverride:
            LanguageBlock(
                language: "controls",
                name: "severity_override",
                phrase: "a severity_override holds",
                attributes: ["rationale", "sources"]
            )
        case .controlsControl:
            LanguageBlock(
                language: "controls",
                name: "control",
                phrase: "a control holds",
                attributes: ["status", "note", "evidence", "reference", "verified_on"]
            )
        case .controlsCompensating:
            LanguageBlock(
                language: "controls",
                name: "compensating",
                phrase: "a compensating control holds",
                attributes: [
                    "reduces_risk_by", "rationale", "sources", "evidence", "reference",
                    "verified_on"
                ]
            )
        case .controlsRecommendation:
            LanguageBlock(
                language: "controls",
                name: "recommendation",
                phrase: "a recommendation holds",
                attributes: ["note", "sources"]
            )

        case .attackTreeDocument:
            LanguageBlock(
                language: "attacktree",
                name: "attack_trees for",
                phrase: "an attack tree file holds",
                attributes: ["catalogue", "tree"]
            )
        case .attackTreeTree:
            LanguageBlock(
                language: "attacktree",
                name: "tree",
                phrase: "a tree holds",
                attributes: [
                    "name", "description", "raises_risk_by", "closed_by", "goal", "all_of",
                    "any_of", "then", "step"
                ]
            )
        case .attackTreeStep:
            LanguageBlock(
                language: "attacktree",
                name: "step",
                phrase: "a step holds",
                attributes: ["note"]
            )
        case .attackTreeAllOf:
            LanguageBlock(
                language: "attacktree",
                name: "all_of",
                phrase: "an all_of holds",
                attributes: ["step", "all_of", "any_of", "then"]
            )
        case .attackTreeAnyOf:
            LanguageBlock(
                language: "attacktree",
                name: "any_of",
                phrase: "an any_of holds",
                attributes: ["step", "all_of", "any_of", "then"]
            )
        case .attackTreeThen:
            LanguageBlock(
                language: "attacktree",
                name: "then",
                phrase: "a then holds",
                attributes: ["step", "all_of", "any_of", "then"]
            )

        case .governanceDocument:
            LanguageBlock(
                language: "governance",
                name: "governance for",
                phrase: "a governance file holds",
                attributes: ["threat", "action", "stale threat", "stale action"]
            )
        case .governanceThreat:
            LanguageBlock(
                language: "governance",
                name: "threat",
                phrase: "a governed threat holds",
                attributes: ["accepted", "work", "stale accepted", "stale work"]
            )
        case .governanceAccepted:
            LanguageBlock(
                language: "governance",
                name: "accepted",
                phrase: "an accepted risk holds",
                attributes: ["owner", "accepted_on", "review_by", "rationale", "sources"]
            )
        case .governanceWork:
            LanguageBlock(
                language: "governance",
                name: "work and action",
                phrase: "planned work holds",
                attributes: [
                    "owner", "effort", "due_by", "status", "acceptance", "note", "sources"
                ]
            )

        case .policyDocument:
            LanguageBlock(
                language: "policy",
                name: "policy",
                phrase: "a policy holds",
                attributes: PolicySource.ruleNames + PolicySource.settingNames,
                listsWithCommasAlone: true
            )

        case .libraryLibrary:
            LanguageBlock(
                language: "lib",
                name: "library",
                phrase: "a library holds",
                attributes: [
                    "name", "catalogue", "technology", "threat", "mitigation", "threat_actor",
                    "category", "severity", "stride", "override", "classification"
                ]
            )
        case .libraryClassification:
            LanguageBlock(
                language: "lib",
                name: "classification",
                phrase: "a classification holds",
                attributes: ["name", "colour"]
            )
        case .libraryOverride:
            LanguageBlock(
                language: "lib",
                name: "override",
                phrase: "an override holds",
                attributes: ["severity", "likelihood", "description", "control"]
            )
        case .libraryCategory:
            LanguageBlock(
                language: "lib",
                name: "category",
                phrase: "this block holds",
                attributes: ["name"]
            )
        case .librarySeverity:
            LanguageBlock(
                language: "lib",
                name: "severity",
                phrase: "this block holds",
                attributes: ["name"]
            )
        case .libraryStride:
            LanguageBlock(
                language: "lib",
                name: "stride",
                phrase: "this block holds",
                attributes: ["name"]
            )
        case .libraryTechnology:
            LanguageBlock(
                language: "lib",
                name: "technology",
                phrase: "a technology holds",
                attributes: ["name", "category", "description", "threats", "encrypts", "control"]
            )
        case .libraryThreat:
            LanguageBlock(
                language: "lib",
                name: "threat",
                phrase: "a threat holds",
                attributes: [
                    "name", "description", "severity", "stride", "impacts", "connection", "zone",
                    "zone_context", "mitre", "control", "applies_to", "boundary", "runs_as",
                    "pathway", "likelihood"
                ]
            )
        case .libraryMitigation:
            LanguageBlock(
                language: "lib",
                name: "mitigation",
                phrase: "a mitigation holds",
                attributes: [
                    "name", "description", "mitigates", "provided_by", "reduces_risk_by", "mode"
                ]
            )
        case .libraryThreatActor:
            LanguageBlock(
                language: "lib",
                name: "threat_actor",
                phrase: "a threat actor holds",
                attributes: [
                    "name", "description", "aliases", "capability", "intent", "performs",
                    "techniques", "performs_catalogue_tier"
                ]
            )
        case .libraryMitre:
            LanguageBlock(
                language: "lib",
                name: "mitre",
                phrase: "a mitre technique holds",
                attributes: ["name", "tactic"]
            )
        }
    }
}

/// The whole vocabulary, for a test that walks it.
public enum LanguageVocabulary {
    /// Every block of every language, in case order.
    public static var blocks: [LanguageBlock] { LanguageBlockId.allCases.map(\.block) }

    /// Every attribute of every block, as `<language>.<block>.<attribute>`.
    /// The parity list is keyed by this word.
    public static var attributeKeys: [String] {
        blocks.flatMap { block in
            block.attributes.map { "\(block.language).\(block.name).\($0)" }
        }
    }
}
