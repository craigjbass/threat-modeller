/// One thing a component holds.
///
/// A secret store is not one blob: SSH keys and browser cookies differ in
/// sensitivity. A component scores at the highest sensitivity it holds.
public struct Asset: Equatable, Sendable {
    public let name: String
    public let sensitivity: DataSensitivity

    public init(name: String, sensitivity: DataSensitivity = .internalData) {
        self.name = name
        self.sensitivity = sensitivity
    }
}

/// One named thing of value the system holds.
///
/// A component states which of these it holds, and a connection states which
/// it carries. The classification takes the words a component's `data` takes,
/// so one scheme names both.
public struct SystemAsset: Equatable, Sendable {
    public let id: String
    public let name: String
    public let classification: DataSensitivity
    public let description: String
    public let owner: String?

    public init(
        id: String,
        name: String,
        classification: DataSensitivity = .internalData,
        description: String = "",
        owner: String? = nil
    ) {
        self.id = id
        self.name = name
        self.classification = classification
        self.description = description
        self.owner = owner
    }
}
