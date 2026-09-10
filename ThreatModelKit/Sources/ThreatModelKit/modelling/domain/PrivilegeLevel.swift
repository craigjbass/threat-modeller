/// The privilege a component runs at. Application-owned.
///
/// The ranks compare, so a flow between two levels is a privilege crossing
/// without anybody drawing a second component or a second zone.
public enum PrivilegeLevel: String, CaseIterable, Equatable, Sendable {
    case user
    case admin
    case root
    case system
    case kernel

    public static let `default` = PrivilegeLevel.user

    public var rank: Int {
        switch self {
        case .user: 1
        case .admin: 2
        case .root: 3
        case .system: 4
        case .kernel: 5
        }
    }

    public var label: String {
        switch self {
        case .user: "User"
        case .admin: "Administrator"
        case .root: "Root"
        case .system: "System"
        case .kernel: "Kernel"
        }
    }
}
