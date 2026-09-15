import Foundation
import ThreatModelKit

/// The ATT&CK data directory on this machine.
///
/// A write goes to a temporary name and is moved into place, so a synchronise
/// that fails part way never leaves half a file where the data should be.
public struct FileSystemAttackData: AttackDataGateway {
    public let directory: String

    public init(directory: String = AttackDataLocation.directory()) {
        self.directory = directory
    }

    public func read(fileName: String) -> String? {
        try? String(contentsOfFile: "\(directory)/\(fileName)", encoding: .utf8)
    }

    public func write(_ text: String, fileName: String) throws {
        try FileManager.default.createDirectory(
            atPath: directory,
            withIntermediateDirectories: true
        )

        let wanted = URL(fileURLWithPath: "\(directory)/\(fileName)")
        let temporary = URL(fileURLWithPath: "\(directory)/.\(fileName).writing")
        try text.write(to: temporary, atomically: true, encoding: .utf8)
        _ = try FileManager.default.replaceItemAt(wanted, withItemAt: temporary)
    }
}
