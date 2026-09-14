import Foundation

// Application-owned, not vendored. Mirrors `Resources/Actors/actors.json`.

struct ActorsFileJSON: Decodable {
    let provider: String
    let displayName: String
    let categories: [ActorCategoryJSON]
    let actors: [ActorJSON]
}

struct ActorCategoryJSON: Decodable {
    let id: String
    let label: String
}

struct ActorJSON: Decodable {
    let id: String
    let name: String
    let category: String
    let description: String
}

// Application-owned, not vendored. Mirrors `Resources/Actors/threat-actors.json`.
//
// A threat actor is an adversary a system faces. It is a different thing from
// the external actor above, which is a box on the diagram.

struct ThreatActorsFileJSON: Decodable {
    let threatActors: [ThreatActorJSON]
}

struct ThreatActorJSON: Decodable {
    let id: String
    let name: String
    let description: String?
    let aliases: [String]?
    let capability: String?
    let intent: String?
    let performs: [String]?
    let techniques: [String]?
    let performsCatalogueTier: String?
}
