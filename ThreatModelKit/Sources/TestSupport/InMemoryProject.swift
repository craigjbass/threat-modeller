import Foundation
import ThreatModelKit

/// A project held in memory, so a test states what is on disk without touching
/// a disk.
public final class InMemoryProject: ProjectSourceGateway, @unchecked Sendable {
    private var files: [String: String] = [:]
    private var directories: Set<String> = []

    public init(root: String = "/project") {
        directories.insert(root)
    }

    /// Puts a file in the project, and every directory above it.
    public func put(_ text: String, at path: String) {
        files[path] = text
        var directory = (path as NSString).deletingLastPathComponent
        while directory.isEmpty == false && directory != "/" {
            directories.insert(directory)
            directory = (directory as NSString).deletingLastPathComponent
        }
    }

    public func text(at path: String) -> String? { files[path] }

    public func discover(root: String) throws -> ProjectLayout {
        guard directories.contains(root) else {
            throw ProjectError.notADirectory(path: root)
        }

        let convention = ProjectConvention.path(root, Self.conventionDirectory)
        let directory = directories.contains(convention) ? convention : root

        let names = files.keys
            .filter { (($0 as NSString).deletingLastPathComponent) == directory }
            .map { ($0 as NSString).lastPathComponent }

        return ProjectLayout(
            root: root,
            directory: directory,
            systems: ProjectConvention.systems(in: directory, fileNames: names)
        )
    }

    public func read(path: String) throws -> String {
        guard let text = files[path] else {
            throw ProjectError.cannotRead(path: path, reason: "there is no such file")
        }
        return text
    }

    public func write(_ text: String, to path: String) throws {
        put(text, at: path)
    }

    public func exists(path: String) -> Bool {
        files[path] != nil || directories.contains(path)
    }
}
