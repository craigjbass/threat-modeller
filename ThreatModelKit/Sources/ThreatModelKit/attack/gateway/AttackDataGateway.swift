import Foundation

/// Reads and writes the ATT&CK data on this machine.
///
/// One port, so the window and the executable read the same directory, and
/// every test answers it in memory.
public protocol AttackDataGateway: Sendable {
    /// The text of one file in the data directory, or nil when it is not
    /// there.
    func read(fileName: String) -> String?
    /// Writes one file into the data directory. A write that fails throws.
    ///
    /// The gateway writes to a temporary name and moves the file into place,
    /// so a half-written file never becomes the data.
    func write(_ text: String, fileName: String) throws
    /// When one file was last written, or nil when it is not there. The
    /// About window states it beside what the machine holds.
    func modified(fileName: String) -> Date?
    /// Where the data sits, for a message a person reads.
    var directory: String { get }
}
