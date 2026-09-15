public protocol VerifyAttackUseCase {
    func execute(_ request: VerifyAttackRequest) -> VerifyAttackResponse
}

public struct VerifyAttackRequest: Equatable, Sendable {
    public let root: String

    public init(root: String) {
        self.root = root
    }
}

public enum VerifyAttackResponse: Equatable, Sendable {
    /// The data on this machine is the data the project's lock file states.
    case matches(tag: String)
    /// The project states no tag, so there is nothing to check against.
    case noLockFile
    /// The lock file states a tag and this machine holds no data.
    case notSynchronised(tag: String)
    /// A file on this machine is not the file the lock states.
    case doesNotMatch(tag: String, fileName: String)
    case notAProject(reason: String)
}

/// Says whether the ATT&CK data on this machine is the data the project agreed
/// on.
///
/// It reads the files and hashes them. No network call and no child process:
/// a person on a train can still ask.
public struct VerifyAttack: VerifyAttackUseCase {
    private let projects: ProjectSourceGateway
    private let data: AttackDataGateway

    public init(projects: ProjectSourceGateway, data: AttackDataGateway) {
        self.projects = projects
        self.data = data
    }

    public func execute(_ request: VerifyAttackRequest) -> VerifyAttackResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch {
            return .notAProject(reason: String(describing: error))
        }

        let lockPath = ProjectConvention.path(layout.directory, AttackLock.fileName)
        guard let lock = (try? projects.read(path: lockPath)).flatMap(AttackLock.read) else {
            return .noLockFile
        }

        for (fileName, checksum) in lock.files.sorted(by: { $0.key < $1.key }) {
            guard let held = data.read(fileName: fileName) else {
                return .notSynchronised(tag: lock.tag)
            }
            guard AttackLock.checksum(held) == checksum else {
                return .doesNotMatch(tag: lock.tag, fileName: fileName)
            }
        }
        return .matches(tag: lock.tag)
    }
}
