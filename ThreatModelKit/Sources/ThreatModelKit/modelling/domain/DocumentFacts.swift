/// What a model states about itself.
///
/// A threat model is a document a team reviews, so it carries what a document
/// carries: what the system is, who wrote it, which version it is, when it was
/// written and when it was last read again. None of it moves a score.
public struct DocumentFacts: Equatable, Sendable {
    public var description: String
    public var authors: [String]
    public var links: [String]
    public var repositories: [String]
    /// `YYYY-MM-DD`, or empty when the file states none.
    public var created: String
    public var reviewed: String
    public var version: String
    /// What the team states that the language does not name, in file order.
    public var attributes: [(name: String, value: String)]

    public init(
        description: String = "",
        authors: [String] = [],
        links: [String] = [],
        repositories: [String] = [],
        created: String = "",
        reviewed: String = "",
        version: String = "",
        attributes: [(name: String, value: String)] = []
    ) {
        self.description = description
        self.authors = authors
        self.links = links
        self.repositories = repositories
        self.created = created
        self.reviewed = reviewed
        self.version = version
        self.attributes = attributes
    }

    public static func == (left: DocumentFacts, right: DocumentFacts) -> Bool {
        left.description == right.description
            && left.authors == right.authors
            && left.links == right.links
            && left.repositories == right.repositories
            && left.created == right.created
            && left.reviewed == right.reviewed
            && left.version == right.version
            && left.attributes.map(\.name) == right.attributes.map(\.name)
            && left.attributes.map(\.value) == right.attributes.map(\.value)
    }

    /// True when the model states nothing about itself.
    public var isEmpty: Bool {
        description.isEmpty && authors.isEmpty && links.isEmpty && repositories.isEmpty
            && created.isEmpty && reviewed.isEmpty && version.isEmpty && attributes.isEmpty
    }
}
