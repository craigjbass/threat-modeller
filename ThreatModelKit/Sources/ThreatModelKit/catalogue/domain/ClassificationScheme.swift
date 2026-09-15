/// One level of a data classification scheme.
///
/// The colour is what a chip on the diagram is painted, stated as a hex
/// string, or nil to let the application choose.
public struct Classification: Equatable, Sendable {
    public let id: String
    public let label: String
    public let colour: String?

    public init(id: String, label: String, colour: String? = nil) {
        self.id = id
        self.label = label
        self.colour = colour
    }
}

/// How a team names the sensitivity of what a component holds.
///
/// The order is the scheme: the first level is the least sensitive and the
/// last is the most. Scoring reads the position, not the id, so a four level
/// scheme and a five level scheme both score:
///
///     rank = position in the order, counting from 1
///     score = the threat's severity rank × the data's rank
///
/// A team whose scheme is `official`, `official-sensitive`, `secret` and
/// `top-secret` scores `secret` at 3, which is what `confidential` scores in
/// the standard scheme, because both sit third.
public struct ClassificationScheme: Equatable, Sendable {
    public let levels: [Classification]
    /// The library that states this scheme, or nil for the standard one.
    public let libraryLabel: String?

    public init(levels: [Classification], libraryLabel: String? = nil) {
        self.levels = levels
        self.libraryLabel = libraryLabel
    }

    /// The four levels this application holds when no library states its own.
    public static let standard = ClassificationScheme(
        levels: [
            Classification(id: "public", label: "Public"),
            Classification(id: "internal", label: "Internal"),
            Classification(id: "confidential", label: "Confidential"),
            Classification(id: "restricted", label: "Restricted")
        ]
    )

    /// The rank of a level, counting from 1. A level this scheme does not hold
    /// ranks 1: it multiplies a severity by the least it can, so an unknown
    /// word never inflates a score.
    public func rank(of id: String) -> Int {
        guard let position = levels.firstIndex(where: { $0.id == id }) else { return 1 }
        return position + 1
    }

    /// What a person reads for that level. A level this scheme does not hold
    /// reads as its own id.
    public func label(of id: String) -> String {
        levels.first { $0.id == id }?.label ?? id
    }

    public func holds(_ id: String) -> Bool {
        levels.contains { $0.id == id }
    }

    /// The most sensitive level this scheme holds, which is what an empty
    /// choice falls back to nothing but the first.
    public var least: Classification? { levels.first }
}
