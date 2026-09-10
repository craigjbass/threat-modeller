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
