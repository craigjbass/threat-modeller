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
    /// Milestone 7 fills this. Written empty and read back ignored, so a
    /// Milestone 6 file still reads once Milestone 7 lands.
    let customTechnologies: [String]
    let severityOverrides: [String: String]
    let implementedControls: [String]
    let pathwayMitigations: PathwayMitigationsJSON
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
}

struct ConnectionJSON: Codable {
    let id: String
    let source: String
    let target: String
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
