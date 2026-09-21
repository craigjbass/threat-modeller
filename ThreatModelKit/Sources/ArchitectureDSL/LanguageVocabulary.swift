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
    /// The words that open the block in a file.
    public let keywords: [String]
    /// The blocks this block opens inside.
    public let within: [LanguageBlockId]
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
        keywords: [String],
        within: [LanguageBlockId],
        phrase: String,
        attributes: [String],
        listsWithCommasAlone: Bool = false
    ) {
        self.language = language
        self.name = name
        self.keywords = keywords
        self.within = within
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
    case archUse
    case archAdversary
    case archClearance
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
    case controlsMitigatedBy
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
                keywords: ["system"],
                within: [],
                phrase: "a system holds",
                attributes: [
                    "catalogue", "owner", "description", "authors", "links", "repositories",
                    "created", "reviewed", "version", "attribute", "technology", "zone",
                    "component", "user", "adversary", "flow", "mitigates", "risk_tolerance",
                    "requires_evidence_above", "assumption", "use_case", "exclusion", "asset",
                    "third_party", "diagram", "faces", "threat_actor", "clearance"
                ]
            )
        case .archUser:
            LanguageBlock(
                language: "arch",
                name: "user",
                keywords: ["user"],
                within: [.archSystem],
                phrase: "a user holds",
                attributes: [
                    "name", "role", "access", "uses", "reaches", "threat_actor", "clearance"
                ]
            )
        case .archUse:
            LanguageBlock(
                language: "arch",
                name: "use",
                keywords: ["uses"],
                within: [.archUser, .archAdversary],
                phrase: "a use holds",
                attributes: ["reaches"]
            )
        case .archAdversary:
            LanguageBlock(
                language: "arch",
                name: "adversary",
                keywords: ["adversary"],
                within: [.archSystem],
                phrase: "an adversary holds",
                attributes: [
                    "name", "role", "access", "uses", "reaches", "threat_actor", "clearance"
                ]
            )
        case .archClearance:
            LanguageBlock(
                language: "arch",
                name: "clearance",
                keywords: ["clearance"],
                within: [.archSystem],
                phrase: "a clearance holds",
                attributes: [
                    "name", "description", "reduces_insider_risk_by", "rationale", "sources"
                ]
            )
        case .archAttribute:
            LanguageBlock(
                language: "arch",
                name: "attribute",
                keywords: ["attribute"],
                within: [.archSystem],
                phrase: "an attribute holds",
                attributes: ["value"]
            )
        case .archAssumption:
            LanguageBlock(
                language: "arch",
                name: "assumption",
                keywords: ["assumption"],
                within: [.archSystem],
                phrase: "an assumption holds",
                attributes: ["text", "owner"]
            )
        case .archDiagram:
            LanguageBlock(
                language: "arch",
                name: "diagram",
                keywords: ["diagram"],
                within: [.archSystem],
                phrase: "a diagram holds",
                attributes: ["kind", "text"]
            )
        case .archThirdParty:
            LanguageBlock(
                language: "arch",
                name: "third_party",
                keywords: ["third_party"],
                within: [.archSystem],
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
                keywords: ["asset"],
                within: [.archSystem],
                phrase: "an asset holds",
                attributes: ["name", "classification", "description", "owner"]
            )
        case .archUseCase:
            LanguageBlock(
                language: "arch",
                name: "use_case",
                keywords: ["use_case"],
                within: [.archSystem],
                phrase: "a use_case holds",
                attributes: ["text"]
            )
        case .archExclusion:
            LanguageBlock(
                language: "arch",
                name: "exclusion",
                keywords: ["exclusion"],
                within: [.archSystem],
                phrase: "an exclusion holds",
                attributes: ["text", "rationale"]
            )
        case .archThreatActor:
            LanguageBlock(
                language: "arch",
                name: "threat_actor",
                keywords: ["threat_actor"],
                within: [.archSystem],
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
                keywords: ["technology"],
                within: [.archSystem],
                phrase: "a technology holds",
                attributes: ["name", "category", "description", "threats", "encrypts", "control"]
            )
        case .archZone:
            LanguageBlock(
                language: "arch",
                name: "zone",
                keywords: ["zone"],
                within: [.archSystem],
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
                keywords: ["component"],
                within: [.archSystem, .archZone],
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
                keywords: ["asset"],
                within: [.archComponent],
                phrase: "an asset holds",
                attributes: ["data"]
            )
        case .archFlow:
            LanguageBlock(
                language: "arch",
                name: "flow",
                keywords: ["flow"],
                within: [.archSystem],
                phrase: "a flow holds",
                attributes: ["kind", "description", "carries", "tags"]
            )
        case .archMitigates:
            LanguageBlock(
                language: "arch",
                name: "mitigates",
                keywords: ["mitigates"],
                within: [.archSystem],
                phrase: "a mitigates edge holds",
                attributes: ["threats", "status", "recommendation"]
            )
        case .archRecommendation:
            LanguageBlock(
                language: "arch",
                name: "recommendation (in mitigates)",
                keywords: ["recommendation"],
                within: [.archMitigates],
                phrase: "a recommendation holds",
                attributes: ["text", "note", "blocked_by", "sources"]
            )

        case .controlsDocument:
            LanguageBlock(
                language: "controls",
                name: "controls for",
                keywords: ["controls"],
                within: [],
                phrase: "a controls file holds",
                attributes: [
                    "catalogue", "tolerance", "threat", "tree", "stale threat", "stale tree"
                ]
            )
        case .controlsTree:
            LanguageBlock(
                language: "controls",
                name: "tree",
                keywords: ["tree"],
                within: [.controlsDocument],
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
                keywords: ["sufficient"],
                within: [.controlsTree],
                phrase: "a sufficient control holds",
                attributes: ["state"]
            )
        case .controlsStep:
            LanguageBlock(
                language: "controls",
                name: "step",
                keywords: ["step"],
                within: [.controlsTree],
                phrase: "a step holds",
                attributes: ["state", "by", "position"]
            )
        case .controlsThreat:
            LanguageBlock(
                language: "controls",
                name: "threat",
                keywords: ["threat"],
                within: [.controlsDocument],
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
                keywords: ["likelihood"],
                within: [.controlsThreat],
                phrase: "a likelihood holds",
                attributes: ["tier", "prior", "rationale", "sources"]
            )
        case .controlsSeverityOverride:
            LanguageBlock(
                language: "controls",
                name: "severity_override",
                keywords: ["severity_override"],
                within: [.controlsThreat],
                phrase: "a severity_override holds",
                attributes: ["rationale", "sources"]
            )
        case .controlsControl:
            LanguageBlock(
                language: "controls",
                name: "control",
                keywords: ["control"],
                within: [.controlsThreat],
                phrase: "a control holds",
                attributes: [
                    "status", "note", "mitigated_by", "evidence", "reference", "verified_on"
                ]
            )
        case .controlsMitigatedBy:
            LanguageBlock(
                language: "controls",
                name: "mitigated_by",
                keywords: ["mitigated_by"],
                within: [.controlsControl],
                phrase: "a mitigated_by block holds",
                attributes: ["reduces_risk_by"]
            )
        case .controlsCompensating:
            LanguageBlock(
                language: "controls",
                name: "compensating",
                keywords: ["compensating"],
                within: [.controlsThreat],
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
                keywords: ["recommendation"],
                within: [.controlsThreat],
                phrase: "a recommendation holds",
                attributes: ["note", "sources"]
            )

        case .attackTreeDocument:
            LanguageBlock(
                language: "attacktree",
                name: "attack_trees for",
                keywords: ["attack_trees"],
                within: [],
                phrase: "an attack tree file holds",
                attributes: ["catalogue", "tree"]
            )
        case .attackTreeTree:
            LanguageBlock(
                language: "attacktree",
                name: "tree",
                keywords: ["tree"],
                within: [.attackTreeDocument],
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
                keywords: ["step"],
                within: [.attackTreeTree, .attackTreeAllOf, .attackTreeAnyOf, .attackTreeThen],
                phrase: "a step holds",
                attributes: ["note"]
            )
        case .attackTreeAllOf:
            LanguageBlock(
                language: "attacktree",
                name: "all_of",
                keywords: ["all_of"],
                within: [.attackTreeTree, .attackTreeAllOf, .attackTreeAnyOf, .attackTreeThen],
                phrase: "an all_of holds",
                attributes: ["step", "all_of", "any_of", "then"]
            )
        case .attackTreeAnyOf:
            LanguageBlock(
                language: "attacktree",
                name: "any_of",
                keywords: ["any_of"],
                within: [.attackTreeTree, .attackTreeAllOf, .attackTreeAnyOf, .attackTreeThen],
                phrase: "an any_of holds",
                attributes: ["step", "all_of", "any_of", "then"]
            )
        case .attackTreeThen:
            LanguageBlock(
                language: "attacktree",
                name: "then",
                keywords: ["then"],
                within: [.attackTreeTree, .attackTreeAllOf, .attackTreeAnyOf, .attackTreeThen],
                phrase: "a then holds",
                attributes: ["step", "all_of", "any_of", "then"]
            )

        case .governanceDocument:
            LanguageBlock(
                language: "governance",
                name: "governance for",
                keywords: ["governance"],
                within: [],
                phrase: "a governance file holds",
                attributes: ["threat", "action", "stale threat", "stale action"]
            )
        case .governanceThreat:
            LanguageBlock(
                language: "governance",
                name: "threat",
                keywords: ["threat"],
                within: [.governanceDocument],
                phrase: "a governed threat holds",
                attributes: ["accepted", "work", "stale accepted", "stale work"]
            )
        case .governanceAccepted:
            LanguageBlock(
                language: "governance",
                name: "accepted",
                keywords: ["accepted"],
                within: [.governanceThreat],
                phrase: "an accepted risk holds",
                attributes: ["owner", "accepted_on", "review_by", "rationale", "sources"]
            )
        case .governanceWork:
            LanguageBlock(
                language: "governance",
                name: "work and action",
                keywords: ["work", "action"],
                within: [.governanceThreat, .governanceDocument],
                phrase: "planned work holds",
                attributes: [
                    "owner", "effort", "due_by", "status", "acceptance", "note", "sources"
                ]
            )

        case .policyDocument:
            LanguageBlock(
                language: "policy",
                name: "policy",
                keywords: ["policy"],
                within: [],
                phrase: "a policy holds",
                attributes: PolicySource.ruleNames + PolicySource.settingNames,
                listsWithCommasAlone: true
            )

        case .libraryLibrary:
            LanguageBlock(
                language: "lib",
                name: "library",
                keywords: ["library"],
                within: [],
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
                keywords: ["classification"],
                within: [.libraryLibrary],
                phrase: "a classification holds",
                attributes: ["name", "colour"]
            )
        case .libraryOverride:
            LanguageBlock(
                language: "lib",
                name: "override",
                keywords: ["override"],
                within: [.libraryLibrary],
                phrase: "an override holds",
                attributes: ["severity", "likelihood", "description", "control"]
            )
        case .libraryCategory:
            LanguageBlock(
                language: "lib",
                name: "category",
                keywords: ["category"],
                within: [.libraryLibrary],
                phrase: "this block holds",
                attributes: ["name"]
            )
        case .librarySeverity:
            LanguageBlock(
                language: "lib",
                name: "severity",
                keywords: ["severity"],
                within: [.libraryLibrary],
                phrase: "this block holds",
                attributes: ["name"]
            )
        case .libraryStride:
            LanguageBlock(
                language: "lib",
                name: "stride",
                keywords: ["stride"],
                within: [.libraryLibrary],
                phrase: "this block holds",
                attributes: ["name"]
            )
        case .libraryTechnology:
            LanguageBlock(
                language: "lib",
                name: "technology",
                keywords: ["technology"],
                within: [.libraryLibrary],
                phrase: "a technology holds",
                attributes: ["name", "category", "description", "threats", "encrypts", "control"]
            )
        case .libraryThreat:
            LanguageBlock(
                language: "lib",
                name: "threat",
                keywords: ["threat"],
                within: [.libraryLibrary],
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
                keywords: ["mitigation"],
                within: [.libraryLibrary],
                phrase: "a mitigation holds",
                attributes: [
                    "name", "description", "mitigates", "provided_by", "reduces_risk_by", "mode"
                ]
            )
        case .libraryThreatActor:
            LanguageBlock(
                language: "lib",
                name: "threat_actor",
                keywords: ["threat_actor"],
                within: [.libraryLibrary],
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
                keywords: ["mitre"],
                within: [.libraryThreat],
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

    /// The block one keyword opens in one language, read with the keywords of
    /// the blocks it sits inside, nearest first.
    public static func blockId(
        keyword: String,
        within: [String],
        language: String
    ) -> LanguageBlockId? {
        let candidates = LanguageBlockId.allCases.filter {
            $0.block.language == language && $0.block.keywords.contains(keyword)
        }
        guard candidates.count > 1 else { return candidates.first }
        for enclosing in within {
            let found = candidates.first { candidate in
                candidate.block.within.contains { $0.block.keywords.contains(enclosing) }
            }
            if let found { return found }
        }
        return candidates.first
    }

    /// Every attribute of every block, as `<language>.<block>.<attribute>`.
    /// The parity list is keyed by this word.
    public static var attributeKeys: [String] {
        blocks.flatMap { block in
            block.attributes.map { "\(block.language).\(block.name).\($0)" }
        }
    }
}
