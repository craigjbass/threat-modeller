import Foundation

/// Fetches the ATT&CK bundle.
///
/// One port, so the window and the executable download the same way and every
/// test answers it without a network call. The application reaches the network
/// through this and through nothing else.
public protocol AttackDownloading: Sendable {
    /// The bytes at that address.
    func download(from address: String) throws -> Data
}

/// What a download can fail with.
public enum AttackDownloadFault: Error, Equatable, Sendable {
    case curlIsNotInstalled
    case cannotRead(reason: String)
    case timedOut

    public var message: String {
        switch self {
        case .curlIsNotInstalled:
            "curl is not installed, so ATT&CK cannot be synchronised"
        case .cannotRead(let reason):
            reason
        case .timedOut:
            "the download did not answer in time"
        }
    }
}
