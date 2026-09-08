import Foundation
import ThreatModelKit

/// Reads a project from the file system.
public struct FileSystemProject: ProjectSourceGateway {
    public init() {}

    /// `FileManager` is not `Sendable`, and `.default` is documented as safe to
    /// call from any thread. Reading it per call keeps the gateway a value.
    private var manager: FileManager { FileManager.default }

    public func discover(root: String) throws -> ProjectLayout {
        var isDirectory: ObjCBool = false
        guard manager.fileExists(atPath: root, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw ProjectError.notADirectory(path: root)
        }

        let convention = (root as NSString)
            .appendingPathComponent(Self.conventionDirectory)
        var directory = root
        if manager.fileExists(atPath: convention, isDirectory: &isDirectory), isDirectory.boolValue {
            directory = convention
        }

        let names: [String]
        do {
            names = try manager.contentsOfDirectory(atPath: directory)
        } catch {
            throw ProjectError.cannotRead(path: directory, reason: String(describing: error))
        }

        return ProjectLayout(
            root: root,
            directory: directory,
            systems: ProjectConvention.systems(in: directory, fileNames: names)
        )
    }

    public func read(path: String) throws -> String {
        do {
            return try String(contentsOfFile: path, encoding: .utf8)
        } catch {
            throw ProjectError.cannotRead(path: path, reason: String(describing: error))
        }
    }

    public func write(_ text: String, to path: String) throws {
        do {
            try manager.createDirectory(
                atPath: (path as NSString).deletingLastPathComponent,
                withIntermediateDirectories: true
            )
            try text.write(toFile: path, atomically: true, encoding: .utf8)
        } catch {
            throw ProjectError.cannotWrite(path: path, reason: String(describing: error))
        }
    }

    public func exists(path: String) -> Bool {
        manager.fileExists(atPath: path)
    }
}
