/// How sensitive the data handled by a component is.
///
/// Application-owned: the catalogue has no opinion on it. The value is the
/// word the file states, so a library that declares its own classification
/// scheme states its own words and this type carries them whole.
///
/// The rank multiplies threat severity to give a risk score, and the rank is
/// the level's position in the scheme in use. `rank` alone reads the standard
/// four; `rank(in:)` reads whichever scheme the project holds.
public struct DataSensitivity: Hashable, Sendable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    /// The word a file states, whichever scheme it belongs to. A caller that
    /// must refuse a word the project does not hold asks `validated(_:in:)`.
    public init(_ rawValue: String) {
        self.rawValue = rawValue
    }

    /// The level, or nil when the scheme does not hold that word.
    public static func validated(
        _ rawValue: String,
        in scheme: ClassificationScheme
    ) -> DataSensitivity? {
        scheme.holds(rawValue) ? DataSensitivity(rawValue: rawValue) : nil
    }

    public static let publicData = DataSensitivity(rawValue: "public")
    public static let internalData = DataSensitivity(rawValue: "internal")
    public static let confidential = DataSensitivity(rawValue: "confidential")
    public static let restricted = DataSensitivity(rawValue: "restricted")

    /// The four levels this application holds when no library states its own.
    public static let allCases: [DataSensitivity] = ClassificationScheme.standard.levels
        .map { DataSensitivity(rawValue: $0.id) }

    /// The rank in the standard scheme. A caller holding a project's own
    /// scheme reads `rank(in:)` instead.
    public var rank: Int { ClassificationScheme.standard.rank(of: rawValue) }

    public func rank(in scheme: ClassificationScheme) -> Int { scheme.rank(of: rawValue) }

    /// The label in the standard scheme.
    public var label: String { ClassificationScheme.standard.label(of: rawValue) }

    public func label(in scheme: ClassificationScheme) -> String { scheme.label(of: rawValue) }
}
