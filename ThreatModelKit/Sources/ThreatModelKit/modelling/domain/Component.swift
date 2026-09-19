/// Whether a component runs in Production today or is a planned change.
///
/// Application-owned, as `DiagramShape` is: the catalogue carries no status
/// vocabulary. A component that states nothing is live, so every file written
/// before this attribute reads and writes unchanged.
public enum ComponentStatus: String, CaseIterable, Equatable, Sendable {
    /// Deployed to Production.
    case live
    /// Planned and not deployed.
    case proposed

    /// What a component with no stated status is.
    public static let `default` = ComponentStatus.live

    public var label: String {
        switch self {
        case .live: "Live"
        case .proposed: "Proposed"
        }
    }
}

/// What a user component states beyond what every component states. The
/// user block design states the block.
public struct UserFacts: Equatable, Sendable {
    /// What the person does with the system. Empty when the file states none.
    public var role: String
    /// The component ids of the clients the user holds, in model order. The
    /// user reaches the system through them; the user-through-a-client
    /// design states the rule.
    public var uses: [String]
    /// The component ids the user reaches, in file order.
    public var reaches: [String]
    /// The threat actor this user is, or nil. A user that names one is faced.
    public var threatActorId: String?
    /// True for an adversary: a threat actor that behaves like a user and is
    /// not a legitimate user. The `adversary` block writes it.
    public var isAdversary: Bool
    /// The id of the clearance this user holds, or nil.
    public var clearanceId: String?

    public init(
        role: String = "",
        uses: [String] = [],
        reaches: [String] = [],
        threatActorId: String? = nil,
        isAdversary: Bool = false,
        clearanceId: String? = nil
    ) {
        self.role = role
        self.uses = uses
        self.reaches = reaches
        self.threatActorId = threatActorId
        self.isAdversary = isAdversary
        self.clearanceId = clearanceId
    }
}

public struct Component: Equatable, Sendable {
    /// The slot a component occupies on the diagram, whatever shape it draws
    /// as.
    ///
    /// The core owns this because zone containment tests a component's centre,
    /// and a centre needs an extent. `footprint(for:)` states what the canvas
    /// paints, and every footprint centres on the centre of this slot, so a
    /// shape change never moves a component.
    public static let size = Size(width: 160, height: 72)

    public let id: ComponentId
    /// What the component is. A person changes it in place, through
    /// `ChangeComponentTechnology`, and the component keeps everything else.
    public var technologyId: TechnologyId
    public var position: Point
    public var sensitivity: DataSensitivity
    public var customName: String?
    /// When true the component raises no threats and suppresses threats on
    /// anything attached to it.
    public var threatsDisabled: Bool
    public var runsAs: PrivilegeLevel
    public var assets: [Asset]
    /// The system asset ids this component holds, in file order.
    public var holds: [String]
    /// The third party that provides this component, or nil.
    public var providedBy: String?
    /// Whether the component states a classification of its own. False means
    /// the component takes the highest classification of what it holds, and
    /// the file writes no `data` line.
    public var statesOwnSensitivity: Bool
    /// The shape the user forced, or nil to let `DiagramShapeMap` decide.
    public var shape: DiagramShape?
    /// The zone that holds this component, or nil when no zone does.
    ///
    /// The field is what every reader reads. Geometry decides it only when a
    /// person moves a node, moves a zone or resizes a zone: `ZoneContainment`
    /// answers then, and the answer is written here. Reading a `.arch` file
    /// takes the nesting the file states, so nothing lays a diagram out to
    /// know which zone holds what.
    ///
    /// A user sits in no zone, whatever rectangle the canvas draws the user
    /// inside: a write on a user keeps nil.
    public var zoneId: ZoneId? {
        get { heldZoneId }
        set { heldZoneId = user == nil ? newValue : nil }
    }
    private var heldZoneId: ZoneId?
    /// What this component states as a user, or nil for a technology
    /// component. A user raises no threats, states no sensitivity and sits
    /// in no zone; the user block design states the rest.
    public var user: UserFacts?

    /// The technology id a user component carries. No catalogue holds it,
    /// so the lookup finds nothing for a user.
    public static let userTechnologyId = TechnologyId("user")

    /// The word a user is called on the palette and on a fresh node.
    public static let userDefaultName = "User"
    /// The words a team files this component under, in model order. A tag
    /// groups elements for a reader; it changes no score.
    public var tags: [String]
    /// Whether the component runs in Production today or is a planned change.
    /// It changes no score: a proposed component raises the threats it will
    /// raise once a team deploys it.
    public var status: ComponentStatus
    /// The version of the software this component runs. Empty when the file
    /// states none.
    public var version: String
    /// The CVE ids the component carries, in file order. A known exploited
    /// one raises every threat on this component to commodity.
    public var cves: [String]
    /// What wrote this component: `terraform` for one an import wrote, nil
    /// for one a person wrote. No control in the window changes it; a save
    /// carries it through unchanged.
    public var source: String?

    public init(
        id: ComponentId,
        technologyId: TechnologyId,
        position: Point,
        sensitivity: DataSensitivity,
        customName: String? = nil,
        threatsDisabled: Bool = false,
        runsAs: PrivilegeLevel = .default,
        assets: [Asset] = [],
        holds: [String] = [],
        providedBy: String? = nil,
        statesOwnSensitivity: Bool = true,
        shape: DiagramShape? = nil,
        zoneId: ZoneId? = nil,
        tags: [String] = [],
        status: ComponentStatus = .default,
        user: UserFacts? = nil,
        version: String = "",
        cves: [String] = [],
        source: String? = nil
    ) {
        self.version = version
        self.cves = cves
        self.source = source
        self.user = user
        self.status = status
        self.tags = tags
        self.id = id
        self.technologyId = technologyId
        self.position = position
        self.sensitivity = sensitivity
        self.customName = customName
        self.threatsDisabled = threatsDisabled
        self.runsAs = runsAs
        self.assets = assets
        self.holds = holds
        self.providedBy = providedBy
        self.statesOwnSensitivity = statesOwnSensitivity
        self.shape = shape
        self.zoneId = zoneId
    }

    /// True for a user, which the canvas draws with the actor shape.
    public var isUser: Bool { user != nil }

    /// True for an adversary: a user the file declares with the `adversary`
    /// keyword.
    public var isAdversary: Bool { user?.isAdversary ?? false }

    /// The id of the clearance this user holds, or nil.
    public var clearanceId: String? { user?.clearanceId }

    /// The size each shape draws at. `size` stays the slot the component
    /// occupies in a layout; this is what the canvas paints, and it centres on
    /// the same point.
    public static func footprint(for shape: DiagramShape) -> Size {
        switch shape {
        case .actor: Size(width: 160, height: 72)
        case .process: Size(width: 104, height: 104)
        case .store: Size(width: 160, height: 64)
        }
    }

    /// The rectangle a shape paints, around the centre of the slot at
    /// `position`. The core owns it because the generated layout measures the
    /// picture it drew.
    public static func footprintRect(at position: Point, shape: DiagramShape) -> Rect {
        let drawn = footprint(for: shape)
        let centre = Point(x: position.x + size.width / 2, y: position.y + size.height / 2)
        return Rect(
            x: centre.x - drawn.width / 2,
            y: centre.y - drawn.height / 2,
            width: drawn.width,
            height: drawn.height
        )
    }

    /// How far below its shape a component writes its provider, its
    /// sensitivity and its zone.
    public static let chipsHeight = 22.0

    /// Everything a component draws: its shape and the chips beneath it,
    /// across the full width of its slot.
    ///
    /// This is what must stay clear, not the shape alone. A boundary drawn
    /// across the chips reads as a boundary drawn across the node.
    public static func drawnRect(at position: Point, shape: DiagramShape) -> Rect {
        let footprint = footprintRect(at: position, shape: shape)
        let centre = Point(x: position.x + size.width / 2, y: position.y + size.height / 2)

        return Rect(
            x: centre.x - size.width / 2,
            y: footprint.minY,
            width: size.width,
            height: footprint.size.height + chipsHeight
        )
    }

    /// The shape to draw: a user is an actor; else the user's own choice,
    /// else the map's answer.
    public func resolvedShape(providerId: String, categoryId: String) -> DiagramShape {
        if isUser { return .actor }
        return shape ?? DiagramShapeMap.derived(providerId: providerId, categoryId: categoryId)
    }

    /// The centre of the slot. `ZoneContainment` tests this point, and every
    /// footprint centres on it.
    public var centre: Point {
        Point(x: position.x + Self.size.width / 2, y: position.y + Self.size.height / 2)
    }

    /// The sensitivity the score uses: the highest of the component's own and
    /// every asset it holds. An asset never lowers what the component states.
    public var effectiveSensitivity: DataSensitivity {
        SensitivityLadder.higher(
            sensitivity,
            SensitivityLadder.highest(of: assets.map(\.sensitivity)) ?? sensitivity
        )
    }
}
