/// The data flow diagram shape a component draws as.
///
/// Application-owned, as `DataSensitivity` and `NetworkZone` are: the
/// catalogue carries no shape vocabulary, and `scripts/update-catalogue.sh`
/// overwrites the vendored library on every refresh.
public enum DiagramShape: String, CaseIterable, Equatable, Sendable {
    case actor
    case process
    case store

    public var label: String {
        switch self {
        case .actor: "Actor"
        case .process: "Process"
        case .store: "Store"
        }
    }
}

/// Which shape a technology draws as when the user states none.
public enum DiagramShapeMap {
    /// The provider the actors library uses. Every technology under it is a
    /// person, a client, a device or another system.
    public static let actorProvider = "actor"

    /// The categories that hold data at rest.
    public static let storeCategories: Set<String> = ["database", "storage", "secrets"]

    /// A component whose technology the catalogue no longer holds carries an
    /// empty provider and an empty category, so it draws as a process.
    public static func derived(providerId: String, categoryId: String) -> DiagramShape {
        if providerId == actorProvider { return .actor }
        if storeCategories.contains(categoryId) { return .store }
        return .process
    }
}
