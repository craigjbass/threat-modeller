/// What a copy holds.
///
/// The identifiers inside are the ones the copy was taken from. They are unique
/// within one document only, and a snippet crosses documents, so
/// `PasteSelection` always mints fresh ones and rewrites the links between them.
public struct SelectionSnippet: Equatable, Sendable {
    public let components: [Component]
    /// Only the links whose both ends are in `components`. A link to something
    /// that was not copied has nothing to attach to.
    public let connections: [Connection]
    public let zones: [Zone]

    public init(components: [Component], connections: [Connection], zones: [Zone]) {
        self.components = components
        self.connections = connections
        self.zones = zones
    }

    public var isEmpty: Bool {
        components.isEmpty && connections.isEmpty && zones.isEmpty
    }
}
