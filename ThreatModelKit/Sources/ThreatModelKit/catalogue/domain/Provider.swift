public struct Provider: Equatable, Sendable {
    public let id: ProviderId
    public let displayName: String

    public init(id: ProviderId, displayName: String) {
        self.id = id
        self.displayName = displayName
    }
}
