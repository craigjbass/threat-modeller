public protocol SetSystemFactsUseCase {
    func execute(_ request: SetSystemFactsRequest) -> SetSystemFactsResponse
}

/// What a system states about itself.
///
/// Every field is optional, and nil states "leave what the model states". An
/// empty string, or an empty list, clears the attribute, and the writer then
/// writes no line for it. One field writes without a caller having to send the
/// other eight.
public struct SetSystemFactsRequest: Equatable, Sendable {
    public let owner: String?
    public let description: String?
    public let authors: [String]?
    public let version: String?
    /// `YYYY-MM-DD`, or empty to state no date.
    public let created: String?
    public let reviewed: String?
    public let links: [String]?
    public let repositories: [String]?

    public init(
        owner: String? = nil,
        description: String? = nil,
        authors: [String]? = nil,
        version: String? = nil,
        created: String? = nil,
        reviewed: String? = nil,
        links: [String]? = nil,
        repositories: [String]? = nil
    ) {
        self.owner = owner
        self.description = description
        self.authors = authors
        self.version = version
        self.created = created
        self.reviewed = reviewed
        self.links = links
        self.repositories = repositories
    }
}

public enum SetSystemFactsResponse: Equatable, Sendable {
    case recorded
    /// A date field holds a text that is not a date. The value names the
    /// attribute: `created` or `reviewed`.
    case notADate(String)

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case let .notADate(attribute):
            message = "The \(attribute) date is written YYYY-MM-DD."
        }
    }
}

/// Writes the document-control attributes of this system's `system` block.
///
/// The report builds its document-control table from them, and the policy rule
/// `system_requires_owner` reads the owner. A date that is not a date is
/// refused before anything is written, so a caller that is not a date picker
/// cannot put a date in the file that the parser then refuses.
public struct SetSystemFacts: SetSystemFactsUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetSystemFactsRequest) -> SetSystemFactsResponse {
        let created = request.created?.trimmingWhitespace()
        let reviewed = request.reviewed?.trimmingWhitespace()

        if let fault = Self.refuses(created, named: "created") { return fault }
        if let fault = Self.refuses(reviewed, named: "reviewed") { return fault }

        return models.mutate(label: ChangeLabel.setSystemFacts) { model in
            if let owner = request.owner { model.owner = owner.trimmingWhitespace() }
            if let description = request.description {
                model.documentFacts.description = description.trimmingWhitespace()
            }
            if let authors = request.authors {
                model.documentFacts.authors = Self.cleaned(authors)
            }
            if let version = request.version {
                model.documentFacts.version = version.trimmingWhitespace()
            }
            if let created { model.documentFacts.created = created }
            if let reviewed { model.documentFacts.reviewed = reviewed }
            if let links = request.links { model.documentFacts.links = Self.cleaned(links) }
            if let repositories = request.repositories {
                model.documentFacts.repositories = Self.cleaned(repositories)
            }
            return .recorded
        }
    }

    /// Why one date field is refused, or nil when the field is a date, is
    /// empty, or was not sent.
    private static func refuses(_ date: String?, named name: String) -> SetSystemFactsResponse? {
        guard let date, date.isEmpty == false else { return nil }
        guard case .success = GovernanceDate.read(date) else { return .notADate(name) }
        return nil
    }

    /// One list, without the whitespace around each item and without the items
    /// that hold nothing.
    private static func cleaned(_ items: [String]) -> [String] {
        items.map { $0.trimmingWhitespace() }.filter { $0.isEmpty == false }
    }
}

public protocol SetSystemAttributeUseCase {
    func execute(_ request: SetSystemAttributeRequest) -> SetSystemAttributeResponse
}

public struct SetSystemAttributeRequest: Equatable, Sendable {
    /// Names the attribute. Writing the same name again changes the block that
    /// is there.
    public let name: String
    public let value: String

    public init(name: String, value: String) {
        self.name = name
        self.value = value
    }
}

public enum SetSystemAttributeResponse: Equatable, Sendable {
    case recorded
    case noName

    public func describe(into message: inout String?) {
        switch self {
        case .recorded: message = nil
        case .noName: message = "An attribute needs a name."
        }
    }
}

/// Writes one free-form `attribute` block into this system's `system` block.
///
/// The language names nine document-control attributes. An `attribute` block
/// is where a team states the tenth thing its own process asks for.
public struct SetSystemAttribute: SetSystemAttributeUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: SetSystemAttributeRequest) -> SetSystemAttributeResponse {
        let name = request.name.trimmingWhitespace()
        guard name.isEmpty == false else { return .noName }
        let value = request.value.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.setSystemAttribute) { model in
            if let already = model.documentFacts.attributes.firstIndex(where: { $0.name == name }) {
                model.documentFacts.attributes[already] = (name: name, value: value)
            } else {
                model.documentFacts.attributes.append((name: name, value: value))
            }
            return .recorded
        }
    }
}

public protocol RemoveSystemAttributeUseCase {
    func execute(_ request: RemoveSystemAttributeRequest) -> RemoveSystemAttributeResponse
}

public struct RemoveSystemAttributeRequest: Equatable, Sendable {
    public let name: String

    public init(name: String) {
        self.name = name
    }
}

public enum RemoveSystemAttributeResponse: Equatable, Sendable {
    case removed
    case noSuchAttribute

    public func describe(into message: inout String?) {
        switch self {
        case .removed: message = nil
        case .noSuchAttribute: message = "This system states no such attribute."
        }
    }
}

/// Takes one free-form `attribute` block off this system.
public struct RemoveSystemAttribute: RemoveSystemAttributeUseCase {
    private let models: ThreatModelGateway

    public init(models: ThreatModelGateway) {
        self.models = models
    }

    public func execute(_ request: RemoveSystemAttributeRequest) -> RemoveSystemAttributeResponse {
        let name = request.name.trimmingWhitespace()

        return models.mutate(label: ChangeLabel.removeSystemAttribute) { model in
            guard let found = model.documentFacts.attributes.firstIndex(where: { $0.name == name })
            else {
                return .noSuchAttribute
            }
            model.documentFacts.attributes.remove(at: found)
            return .removed
        }
    }
}
