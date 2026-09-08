public struct Component: Equatable, Sendable {
    /// The footprint a component occupies on the diagram.
    ///
    /// The core owns this because zone containment tests a component's centre,
    /// and a centre needs an extent. The canvas draws at this size rather than
    /// holding a second constant of its own.
    public static let size = Size(width: 160, height: 72)

    public let id: ComponentId
    public let technologyId: TechnologyId
    public var position: Point
    public var sensitivity: DataSensitivity
    public var customName: String?
    /// When true the component raises no threats and suppresses threats on
    /// anything attached to it. Honoured from Milestone 2 onwards.
    public var threatsDisabled: Bool

    public init(
        id: ComponentId,
        technologyId: TechnologyId,
        position: Point,
        sensitivity: DataSensitivity,
        customName: String? = nil,
        threatsDisabled: Bool = false
    ) {
        self.id = id
        self.technologyId = technologyId
        self.position = position
        self.sensitivity = sensitivity
        self.customName = customName
        self.threatsDisabled = threatsDisabled
    }

    /// The centre of the footprint. `ZoneContainment` tests this point.
    public var centre: Point {
        Point(x: position.x + Self.size.width / 2, y: position.y + Self.size.height / 2)
    }
}
