public struct ComponentId: Hashable, Sendable, CustomStringConvertible {
    public let value: String
    public init(_ value: String) { self.value = value }
    public var description: String { value }
}

public struct Component: Equatable, Sendable {
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
}
