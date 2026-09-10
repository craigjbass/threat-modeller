/// What a flow between two components is.
///
/// Application-owned, as `DataSensitivity` and `NetworkZone` are: the
/// catalogue carries no flow vocabulary. A threat states the kinds it applies
/// to, and a threat that states none applies to a network flow only, so a
/// local call raises no threat about TLS.
public enum FlowKind: String, CaseIterable, Equatable, Sendable {
    case network
    case ipc
    case file
    case syscall
    case human

    public static let `default` = FlowKind.network

    public var label: String {
        switch self {
        case .network: "Network"
        case .ipc: "Local IPC"
        case .file: "File"
        case .syscall: "System Call"
        case .human: "Human"
        }
    }
}
