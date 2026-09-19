/// A vetting level a person holds, and how far it answers the threats an
/// insider performs.
///
/// The team writing the model defines the levels. The application ships none,
/// so a scheme of two levels and a scheme of six each state themselves.
public struct Clearance: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    /// 0 to 100.
    public let reducesInsiderRiskBy: Int
    public let rationale: String
    /// Where the rationale comes from. Empty when a person names none.
    public let sources: [String]

    public init(
        id: String,
        name: String,
        description: String = "",
        reducesInsiderRiskBy: Int,
        rationale: String,
        sources: [String] = []
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.reducesInsiderRiskBy = reducesInsiderRiskBy
        self.rationale = rationale
        self.sources = sources
    }

    /// The widest reduction a clearance may state.
    public static let widestReduction = 100
}
