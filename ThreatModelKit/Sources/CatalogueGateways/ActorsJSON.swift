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
