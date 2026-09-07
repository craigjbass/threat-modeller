/// How sensitive the data handled by a component is. Application-owned: the
/// catalogue has no opinion on it. The rank multiplies threat severity to give
/// a risk score.
public enum DataSensitivity: String, CaseIterable, Equatable, Sendable {
    case publicData = "public"
    case internalData = "internal"
    case confidential = "confidential"
    case restricted = "restricted"

    public var rank: Int {
        switch self {
        case .publicData: 1
        case .internalData: 2
        case .confidential: 3
        case .restricted: 4
        }
    }

    public var label: String {
        switch self {
        case .publicData: "Public"
        case .internalData: "Internal"
        case .confidential: "Confidential"
        case .restricted: "Restricted"
        }
    }
}
