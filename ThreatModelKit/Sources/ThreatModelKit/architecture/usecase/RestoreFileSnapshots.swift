public protocol RestoreFileSnapshotsUseCase {
    func execute(_ request: RestoreFileSnapshotsRequest) -> RestoreFileSnapshotsResponse
}

public struct RestoreFileSnapshotsRequest: Equatable, Sendable {
    public let snapshots: [FileSnapshot]

    public init(snapshots: [FileSnapshot]) {
        self.snapshots = snapshots
    }
}

public enum RestoreFileSnapshotsResponse: Equatable, Sendable {
    case restored
    case cannotWrite(reason: String)
}

/// Puts files back the way a snapshot read them, for taking a merge back.
///
/// A snapshot with text writes the text. A snapshot with no text deletes
/// the file, because the file was absent when the snapshot read it. It is
/// the one way the window puts bytes into a file it did not compile.
public struct RestoreFileSnapshots: RestoreFileSnapshotsUseCase {
    private let projects: ProjectSourceGateway

    public init(projects: ProjectSourceGateway) {
        self.projects = projects
    }

    public func execute(_ request: RestoreFileSnapshotsRequest) -> RestoreFileSnapshotsResponse {
        for snapshot in request.snapshots {
            do {
                if let text = snapshot.text {
                    try projects.write(text, to: snapshot.path)
                } else if projects.exists(path: snapshot.path) {
                    try projects.delete(path: snapshot.path)
                }
            } catch {
                return .cannotWrite(reason: String(describing: error))
            }
        }
        return .restored
    }
}
