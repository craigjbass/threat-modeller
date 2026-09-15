/// What a third party provides, so a reader can group a vendor review.
public enum ThirdPartyKind: String, CaseIterable, Equatable, Sendable {
    case saas
    case openSource = "open_source"
    case infrastructure
    case contractor

    public var label: String {
        switch self {
        case .saas: "SaaS"
        case .openSource: "Open source"
        case .infrastructure: "Infrastructure"
        case .contractor: "Contractor"
        }
    }
}

/// What happens to this system when a third party stops.
public enum UptimeDependency: String, CaseIterable, Equatable, Sendable {
    /// The system runs as it always did.
    case none
    /// The system runs, and something a person notices stops working.
    case degraded
    /// The system stops.
    case hard
    /// The system runs, and the team cannot operate it.
    case operational

    public var label: String {
        switch self {
        case .none: "None"
        case .degraded: "Degraded"
        case .hard: "Hard"
        case .operational: "Operational"
        }
    }
}

/// One party outside this team the system depends on.
///
/// A box on the diagram states a technology. This states which company,
/// project or person runs it, what the team pays, and what happens when it
/// stops.
public struct ThirdParty: Equatable, Sendable {
    public let id: String
    public let name: String
    public let description: String
    public let kind: ThirdPartyKind
    public let payingCustomer: Bool
    public let uptime: UptimeDependency
    public let uptimeNotes: String
    public let owner: String?
    public let link: String?

    public init(
        id: String,
        name: String,
        description: String = "",
        kind: ThirdPartyKind = .saas,
        payingCustomer: Bool = false,
        uptime: UptimeDependency = .none,
        uptimeNotes: String = "",
        owner: String? = nil,
        link: String? = nil
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.kind = kind
        self.payingCustomer = payingCustomer
        self.uptime = uptime
        self.uptimeNotes = uptimeNotes
        self.owner = owner
        self.link = link
    }
}


/// One picture a team keeps beside the diagram the canvas draws.
///
/// A sequence diagram of a login, or a deployment diagram, says something the
/// data-flow diagram cannot. The report writes it as a fenced block, so a
/// reader sees it where the rest of the model is.
public struct SystemDiagram: Equatable, Sendable {
    public let label: String
    /// `mermaid`, the one kind this application draws.
    public let kind: String
    /// The picture's source, byte for byte as the team wrote it.
    public let text: String

    public init(label: String, kind: String = "mermaid", text: String) {
        self.label = label
        self.kind = kind
        self.text = text
    }
}
