/// What a zone is a boundary of. Application-owned.
///
/// A network zone raises the network threat set. A privilege zone raises the
/// privilege threat set. Neither raises the other's, so a `uid 0` boundary no
/// longer collects threats about network misconfiguration.
public enum ZoneBoundary: String, CaseIterable, Equatable, Sendable {
    case network
    case privilege

    public static let `default` = ZoneBoundary.network

    public var label: String {
        switch self {
        case .network: "Network Boundary"
        case .privilege: "Privilege Boundary"
        }
    }
}
