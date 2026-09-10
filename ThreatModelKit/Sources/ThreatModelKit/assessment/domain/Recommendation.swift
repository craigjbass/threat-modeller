/// What a person says should be done about a threat.
///
/// It is not an answer and it does not move a score. It is the work the
/// assessment found, and the report gives it its own section.
public struct Recommendation: Equatable, Sendable {
    public let text: String
    public let note: String?
    /// Where the recommendation comes from. Empty when a person names none.
    public let sources: [String]

    public init(text: String, note: String? = nil, sources: [String] = []) {
        self.text = text
        self.note = note
        self.sources = sources
    }
}
