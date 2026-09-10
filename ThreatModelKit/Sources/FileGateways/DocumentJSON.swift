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
    let pathwayMitigations: PathwayMitigationsJSON
    /// Version 4 adds these two. A version 1, 2 or 3 file has neither.
    let mitigatesEdges: [MitigatesEdgeJSON]?
    let recommendations: [String: [RecommendationJSON]]?
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
}

struct ConnectionJSON: Codable {
    let id: String
    let source: String
    let target: String
    let kind: String?
    let description: String?
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
}
