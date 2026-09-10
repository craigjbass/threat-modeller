/// Whether a zone is exposed or protected.
///
/// Application-owned, as `DataSensitivity` is: the catalogue carries no zone
/// vocabulary. Only a private zone reduces risk and only a private zone raises
/// zone threats.
public enum NetworkZone: String, CaseIterable, Equatable, Sendable {
    case publicZone = "public"
    case privateZone = "private"

    public var label: String {
        switch self {
        case .publicZone: "Public Zone"
        case .privateZone: "Private Zone"
        }
    }
}

/// The kind of network a zone stands for. Application-owned.
public enum ZoneNetworkType: String, CaseIterable, Equatable, Sendable {
    case generic
    case vpc
    case subnet
    case onPremises = "on-premises"
    case dmz
    case management
    case data

    public var label: String {
        switch self {
        case .generic: "Generic Network"
        case .vpc: "VPC"
        case .subnet: "Subnet"
        case .onPremises: "On-Premises"
        case .dmz: "DMZ"
        case .management: "Management Network"
        case .data: "Data Network"
        }
    }
}

/// A network trust zone drawn on the diagram.
///
/// A zone stores its rectangle and its properties and nothing else. Which
/// components it holds is derived from the geometry by `ZoneContainment`, so
/// there is no stored membership to go stale when a component or a zone moves.
public struct Zone: Equatable, Sendable {
    public static let defaultRiskReductionPercent = 20
    public static let minimumSize = Size(width: 120, height: 100)

    public let id: ZoneId
    public var rect: Rect
    public var name: String?
    public var networkZone: NetworkZone
    public var networkType: ZoneNetworkType
    public var riskReductionEnabled: Bool
    public var riskReductionPercent: Int
    public var boundary: ZoneBoundary
    public var description: String?

    public init(
        id: ZoneId,
        rect: Rect,
        name: String? = nil,
        networkZone: NetworkZone = .privateZone,
        networkType: ZoneNetworkType = .generic,
        riskReductionEnabled: Bool = true,
        riskReductionPercent: Int = Zone.defaultRiskReductionPercent,
        boundary: ZoneBoundary = .default,
        description: String? = nil
    ) {
        self.id = id
        self.rect = rect
        self.name = name
        self.networkZone = networkZone
        self.networkType = networkType
        self.riskReductionEnabled = riskReductionEnabled
        self.riskReductionPercent = riskReductionPercent
        self.boundary = boundary
        self.description = description
    }

    /// Spec section 5.3: the user's own name, else the network type label when
    /// the type is not `generic`, else the network zone label.
    public var displayName: String {
        let trimmed = name?.trimmingWhitespace() ?? ""
        if trimmed.isEmpty == false { return trimmed }
        if networkType != .generic { return networkType.label }
        return networkZone.label
    }
}

extension String {
    /// `Foundation.trimmingCharacters` is not used here: the core imports
    /// Foundation for value types only, and this is the whole need.
    func trimmingWhitespace() -> String {
        var characters = Array(self)
        while let first = characters.first, first.isWhitespace { characters.removeFirst() }
        while let last = characters.last, last.isWhitespace { characters.removeLast() }
        return String(characters)
    }
}
