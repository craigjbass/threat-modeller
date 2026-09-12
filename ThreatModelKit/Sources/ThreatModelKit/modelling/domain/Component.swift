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
    public let technologyId: TechnologyId
    public var position: Point
    public var sensitivity: DataSensitivity
    public var customName: String?
    /// When true the component raises no threats and suppresses threats on
    /// anything attached to it. Honoured from Milestone 2 onwards.
    public var threatsDisabled: Bool
    public var runsAs: PrivilegeLevel
    public var assets: [Asset]
    /// The shape the user forced, or nil to let `DiagramShapeMap` decide.
    public var shape: DiagramShape?

    public init(
        id: ComponentId,
        technologyId: TechnologyId,
        position: Point,
        sensitivity: DataSensitivity,
        customName: String? = nil,
        threatsDisabled: Bool = false,
        runsAs: PrivilegeLevel = .default,
        assets: [Asset] = [],
        shape: DiagramShape? = nil
    ) {
        self.id = id
        self.technologyId = technologyId
        self.position = position
        self.sensitivity = sensitivity
        self.customName = customName
        self.threatsDisabled = threatsDisabled
        self.runsAs = runsAs
        self.assets = assets
        self.shape = shape
    }

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

    /// The shape to draw: the user's own choice, else the map's answer.
    public func resolvedShape(providerId: String, categoryId: String) -> DiagramShape {
        shape ?? DiagramShapeMap.derived(providerId: providerId, categoryId: categoryId)
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
