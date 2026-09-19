import Foundation

// Mirrors the file of spec section 8 exactly. These types exist only so the
// codec can build Domain objects; nothing outside this target sees them.

struct DocumentJSON: Codable {
    let formatVersion: Int
    let name: String
    let createdAt: Date
    let updatedAt: Date
    let catalogue: CatalogueStampJSON?
    let components: [ComponentJSON]
    let connections: [ConnectionJSON]
    let zones: [ZoneJSON]
    let customTechnologies: [CustomTechnologyJSON]
    let severityOverrides: [String: String]
    let implementedControls: [String]
    /// Version 3 adds these. A version 1 or 2 file has neither, and its
    /// `implementedControls` become `implemented` statuses.
    let controlStatuses: [String: String]?
    let compensatingControls: [String: [CompensatingControlJSON]]?
    /// Version 10 adds what proves a control. A file at version 9 or below
    /// states none.
    let controlProofs: [String: ControlProofJSON]?
    /// Version 11 adds what a person wrote about a control, beside its
    /// evidence. A file at version 10 or below states none.
    let controlNotes: [String: String]?
    let pathwayMitigations: PathwayMitigationsJSON
    /// Version 4 adds these two. A version 1, 2 or 3 file has neither.
    let mitigatesEdges: [MitigatesEdgeJSON]?
    let recommendations: [String: [RecommendationJSON]]?
    /// Version 5 adds these four. A version 1 through 4 file has none of
    /// them.
    let likelihoodFindings: [String: LikelihoodFindingJSON]?
    let severityDecisions: [String: SeverityDecisionJSON]?
    let assumptions: [SystemAssumptionJSON]?
    /// Absent means the file states no tolerance, so a check uses `.low`.
    let riskTolerance: String?
    /// Version 8 adds these two: who owns the system, and what the model
    /// states about itself. A file at version 7 or below holds neither.
    let owner: String?
    let documentFacts: DocumentFactsJSON?
    /// Version 9 adds these three: what a team stated a threat harms, what a
    /// person does with the system, and what the model does not cover.
    let impactOverrides: [String: [String]]?
    let useCases: [SystemUseCaseJSON]?
    let exclusions: [SystemExclusionJSON]?
    /// The named things of value the system holds.
    let systemAssets: [SystemAssetJSON]?
    /// The parties outside this team the system depends on.
    let thirdParties: [ThirdPartyJSON]?
    /// The pictures the team keeps beside the diagram.
    let diagrams: [SystemDiagramJSON]?
}

struct SystemDiagramJSON: Codable {
    let label: String
    let kind: String
    let text: String
}

struct ThirdPartyJSON: Codable {
    let id: String
    let name: String
    let description: String
    let kind: String
    let payingCustomer: Bool
    let uptime: String
    let uptimeNotes: String
    let owner: String?
    let link: String?
}

struct SystemAssetJSON: Codable {
    let id: String
    let name: String
    let classification: String
    let description: String
    let owner: String?
}

struct SystemUseCaseJSON: Codable {
    let label: String
    let text: String
}

struct SystemExclusionJSON: Codable {
    let label: String
    let text: String
    let rationale: String
}

struct LikelihoodFindingJSON: Codable {
    let label: String
    let likelihood: String
    let rationale: String
    let sources: [String]?
}

struct SeverityDecisionJSON: Codable {
    let severityId: String
    let rationale: String
    let sources: [String]?
}

struct SystemAssumptionJSON: Codable {
    let label: String
    let text: String
    let owner: String?
}

struct AssetJSON: Codable {
    let name: String
    let sensitivity: String
}

struct MitigatesEdgeJSON: Codable {
    let source: String
    let target: String
    let threatIds: [String]
    let reducesRiskBy: Int
    /// Absent means `adopted`, so a file written before this field existed
    /// keeps its numbers.
    let status: String?
    /// Version 6 adds this.
    let action: EdgeActionJSON?
}

/// Version 6 adds this. A file written before it has none, and its edges keep
/// their numbers.
struct EdgeActionJSON: Codable {
    let label: String
    let text: String?
    let note: String?
    let blockedBy: String?
    let sources: [String]?
}

struct RecommendationJSON: Codable {
    let text: String
    let note: String?
    let sources: [String]?
}

struct CustomTechnologyJSON: Codable {
    let id: String
    let name: String
    let category: String
    let description: String
    let threatIds: [String]
    let enforcesEncryption: Bool
    /// The controls this technology brings. Absent in a file written before
    /// format version 7.
    let controls: [String]?
}

/// What the model states about itself. Absent in a file written before format
/// version 8.
struct DocumentFactsJSON: Codable {
    let description: String?
    let authors: [String]?
    let links: [String]?
    let repositories: [String]?
    let created: String?
    let reviewed: String?
    let version: String?
    let attributes: [AttributeJSON]?

    struct AttributeJSON: Codable {
        let name: String
        let value: String
    }
}

struct CatalogueStampJSON: Codable {
    let repository: String
    let tag: String
}

struct ComponentJSON: Codable {
    let id: String
    let technologyId: String
    let x: Double
    let y: Double
    let sensitivity: String
    let customName: String?
    let threatsDisabled: Bool
    let runsAs: String?
    let assets: [AssetJSON]?
    /// The shape the user forced. Absent means the derivation decides.
    let shape: String?
    /// The zone that holds this component. Absent in a file written before
    /// format version 7; the codec then reads it from the coordinates.
    let zoneId: String?
    /// Version 9 adds these two: the system asset ids this component holds,
    /// and whether it states a classification of its own.
    let holds: [String]?
    let statesOwnSensitivity: Bool?
    /// The third party that provides this component.
    let providedBy: String?
    /// What the component states as a user. Absent for a technology
    /// component, and in a file written before the user block.
    let user: UserJSON?
}

struct UserJSON: Codable {
    let role: String
    /// Absent in a file written before the user-through-a-client design.
    let uses: [String]?
    let reaches: [String]
    let threatActorId: String?
    /// Absent in a file written before the adversary alias.
    let isAdversary: Bool?
    /// Absent in a file written before the clearance block.
    let clearanceId: String?
}

struct ConnectionJSON: Codable {
    let id: String
    let source: String
    let target: String
    let kind: String?
    let description: String?
    /// Version 9 adds this: the system asset ids this connection carries.
    let carries: [String]?
}

struct ZoneJSON: Codable {
    let id: String
    let x: Double
    let y: Double
    let width: Double
    let height: Double
    let name: String?
    let networkZone: String
    let networkType: String
    let riskReductionEnabled: Bool
    let riskReductionPercent: Int
    let boundary: String?
    let description: String?
}

struct CompensatingControlJSON: Codable {
    let label: String
    let reducesRiskBy: Int
    let rationale: String
    let sources: [String]?
    /// Version 10 adds these three. A file at version 9 or below states none.
    let evidence: String?
    let reference: String?
    let verifiedOn: String?
}

/// What proves one control is in place: the tier, the reference and the
/// verified-on date. Any of the three may be absent.
struct ControlProofJSON: Codable {
    let evidence: String?
    let reference: String?
    let verifiedOn: String?
}

struct PathwayMitigationsJSON: Codable {
    let isMasterEnabled: Bool
    let configs: [String: PathwayMitigationConfigJSON]
}

struct PathwayMitigationConfigJSON: Codable {
    let isEnabled: Bool
    let mode: String
    let reductionPercent: Int
}

struct SelectionJSON: Codable {
    let formatVersion: Int
    let components: [ComponentJSON]
    let connections: [ConnectionJSON]
    let zones: [ZoneJSON]
    /// The user's answers about what the selection holds. Absent from
    /// clipboard text an earlier build wrote, and a paste of that text puts
    /// the elements back with no answers, the way it always did. The document
    /// format is unchanged, so the format version does not move.
    let controlStatuses: [String: String]?
    let severityOverrides: [String: String]?
    let likelihoodFindings: [String: LikelihoodFindingJSON]?
}
