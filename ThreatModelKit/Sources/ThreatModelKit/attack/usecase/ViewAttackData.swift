import Foundation

public protocol ViewAttackDataUseCase {
    func execute(_ request: ViewAttackDataRequest) -> ViewAttackDataResponse
}

public struct ViewAttackDataRequest: Equatable, Sendable {
    public init() {}
}

public enum ViewAttackDataResponse: Equatable, Sendable {
    /// What this machine holds: the tag, the counts, and when the data was
    /// written. `writtenAt` is nil when the file states no date.
    case held(tag: String, groups: Int, techniques: Int, writtenAt: Date?)
    /// This machine holds no ATT&CK data.
    case nothingHeld
}

/// States the ATT&CK data this machine holds.
///
/// It reads the two files in the data directory and nothing else. No project,
/// no network call: the About window asks with any project open, and the
/// answer is the same one `threatmodeller attack verify` hashes.
public struct ViewAttackData: ViewAttackDataUseCase {
    private let data: AttackDataGateway

    public init(data: AttackDataGateway) {
        self.data = data
    }

    public func execute(_ request: ViewAttackDataRequest) -> ViewAttackDataResponse {
        guard let groupsText = data.read(fileName: AttackDataLocation.groupsFileName),
              let techniquesText = data.read(fileName: AttackDataLocation.techniquesFileName),
              let tag = AttackFiles.release(from: groupsText) else {
            return .nothingHeld
        }

        return .held(
            tag: tag,
            groups: AttackFiles.groups(from: groupsText).count,
            techniques: AttackFiles.techniques(from: techniquesText).count,
            writtenAt: data.modified(fileName: AttackDataLocation.techniquesFileName)
        )
    }
}
