/// The aggregate a threat model is assessed from. Connections, zones, overrides
/// and implemented controls join it in later milestones.
public struct ThreatModel: Equatable, Sendable {
    public var name: String
    public var components: [Component]

    public init(name: String = "Untitled", components: [Component] = []) {
        self.name = name
        self.components = components
    }
}
