public protocol ReadProjectFingerprintUseCase {
    func execute(_ request: ReadProjectFingerprintRequest) -> ReadProjectFingerprintResponse
}

public struct ReadProjectFingerprintRequest: Equatable, Sendable {
    public let root: String
    public init(root: String) { self.root = root }
}

public enum ReadProjectFingerprintResponse: Equatable, Sendable {
    /// One number per file, by path. Two reads of the same text answer the
    /// same number inside one run of the application.
    case read(fingerprint: [String: Int])
    case notAProject(reason: String)
}

/// Answers a number per source file, so a caller can tell whether a file
/// changed since it last read one.
///
/// The number is `String.hashValue`. Swift seeds that hash once per process,
/// so it is stable while the application runs and means nothing after it
/// stops. Nothing writes it to a file.
public struct ReadProjectFingerprint: ReadProjectFingerprintUseCase {
    private let projects: ProjectSourceGateway

    public init(projects: ProjectSourceGateway) {
        self.projects = projects
    }

    public func execute(_ request: ReadProjectFingerprintRequest) -> ReadProjectFingerprintResponse {
        do {
            let layout = try projects.discover(root: request.root)
            var fingerprint: [String: Int] = [:]

            for system in layout.systems {
                // Every file a system is read from, so a change to any of
                // them is a change to the system. A split system reads many
                // architecture, controls and attack tree files, not one.
                let paths = system.architecturePaths
                    + system.controlsPaths
                    + system.attackTreePaths
                    + [system.governancePath]
                for path in paths {
                    guard projects.exists(path: path) else { continue }
                    fingerprint[path] = try projects.read(path: path).hashValue
                }
            }

            // Every system reads every library, so a library edit is a change
            // to the project the same way a header file edit is.
            for path in layout.libraryPaths {
                guard projects.exists(path: path) else { continue }
                fingerprint[path] = try projects.read(path: path).hashValue
            }
            return .read(fingerprint: fingerprint)
        } catch ProjectError.notADirectory(let path) {
            return .notAProject(reason: "\(path) is not a directory")
        } catch {
            return .notAProject(reason: String(describing: error))
        }
    }
}
