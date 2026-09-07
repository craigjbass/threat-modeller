import Foundation

// Mirrors the vendored JSON exactly. These types exist only so the gateway can
// build Domain objects; nothing outside this target sees them.

struct TaxonomyJSON: Decodable {
    struct Labelled: Decodable {
        let id: String
        let label: String
    }

    struct Category: Decodable {
        let id: String
        let label: String
        let presetThreatIds: [String]
    }

    let stride: [Labelled]
    let severities: [Labelled]
    let categories: [Category]
}

struct ProviderFileJSON: Decodable {
    let provider: String
    let displayName: String
    let services: [ServiceJSON]
}

struct ServiceJSON: Decodable {
    struct ConnectionSecurity: Decodable {
        let enforcesEncryption: Bool?
        let internalOnly: Bool?
    }

    let id: String
    let name: String
    let provider: String
    let category: String
    let description: String
    let threatIds: [String]
    let connectionSecurity: ConnectionSecurity?
    let threatContext: [String: String]?
    let threatMitigations: [String: [String]]?
}

struct ThreatsFileJSON: Decodable {
    let threats: [ThreatJSON]
}

struct ThreatJSON: Decodable {
    struct Mitre: Decodable {
        let id: String
        let name: String
        let tactic: String
    }

    struct ControlEntry: Decodable {
        let id: String
        let description: String
    }

    let id: String
    let name: String
    let description: String
    let severity: String
    let stride: [String]
    let mitreTechniques: [Mitre]
    let controls: [ControlEntry]
    let isConnectionThreat: Bool?
    let isZoneThreat: Bool?
    let isPathwayThreat: Bool?
    let zoneContext: String?
}
