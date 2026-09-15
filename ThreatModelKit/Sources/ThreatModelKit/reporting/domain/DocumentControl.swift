/// What a report says about the document itself.
///
/// A reader who picks up a threat model asks who owns it, who wrote it, which
/// version it is and when it was last read again. A system that states none of
/// that gets no table: an empty table says nothing and takes a page.
public struct DocumentControl: Equatable, Sendable {
    /// How long a model may go unread before the summary says so.
    ///
    /// Six months. A model states what a system was, and a system changes; a
    /// model nobody has read for half a year states what a system was, not
    /// what it is.
    public static let reviewIntervalDays = 180

    public let systemName: String
    public let description: String?
    public let owner: String?
    public let authors: [String]
    public let version: String?
    public let created: String?
    public let reviewed: String?
    public let catalogueTag: String?
    public let links: [String]
    public let repositories: [String]
    /// What the team states that the language does not name.
    public let attributes: [(name: String, value: String)]

    public init(
        systemName: String,
        description: String? = nil,
        owner: String? = nil,
        authors: [String] = [],
        version: String? = nil,
        created: String? = nil,
        reviewed: String? = nil,
        catalogueTag: String? = nil,
        links: [String] = [],
        repositories: [String] = [],
        attributes: [(name: String, value: String)] = []
    ) {
        self.systemName = systemName
        self.description = description
        self.owner = owner
        self.authors = authors
        self.version = version
        self.created = created
        self.reviewed = reviewed
        self.catalogueTag = catalogueTag
        self.links = links
        self.repositories = repositories
        self.attributes = attributes
    }

    public static func == (left: DocumentControl, right: DocumentControl) -> Bool {
        left.systemName == right.systemName
            && left.description == right.description
            && left.owner == right.owner
            && left.authors == right.authors
            && left.version == right.version
            && left.created == right.created
            && left.reviewed == right.reviewed
            && left.catalogueTag == right.catalogueTag
            && left.links == right.links
            && left.repositories == right.repositories
            && left.attributes.map(\.name) == right.attributes.map(\.name)
            && left.attributes.map(\.value) == right.attributes.map(\.value)
    }

    /// True when the system states something worth a table. The system's name
    /// alone is the report's title, so it is not enough.
    public var statesSomething: Bool {
        description != nil || owner != nil || version != nil || created != nil
            || reviewed != nil || authors.isEmpty == false || links.isEmpty == false
            || repositories.isEmpty == false || attributes.isEmpty == false
    }

    /// True when the model has not been read again inside the interval. A
    /// model that states no `reviewed` date is not overdue: nobody said it
    /// ever was read.
    public func isOverdue(on today: GovernanceDate) -> Bool {
        guard let reviewed, case .success(let date) = GovernanceDate.read(reviewed) else {
            return false
        }
        return date.daysUntil(today) > Self.reviewIntervalDays
    }
}
