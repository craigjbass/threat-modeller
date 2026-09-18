import Foundation
import ThreatModelKit

/// A project held in memory, so a test states what is on disk without touching
/// a disk.
public final class InMemoryProject: ProjectSourceGateway, @unchecked Sendable {
    private var files: [String: String] = [:]
    private var directories: Set<String> = []
    /// How many times a save wrote each path, for a test that states which
    /// files a save touched.
    private var writeCounts: [String: Int] = [:]

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

    /// Every path this project holds, for a test that states what was
    /// written.
    public var everyPath: [String] { Array(files.keys) }

    public func discover(root: String) throws -> ProjectLayout {
        guard directories.contains(root) else {
            throw ProjectError.notADirectory(path: root)
        }

        let convention = ProjectConvention.path(root, Self.conventionDirectory)
        let directory = directories.contains(convention) ? convention : root

        let names = files.keys
            .filter { (($0 as NSString).deletingLastPathComponent) == directory }
            .map { ($0 as NSString).lastPathComponent }

        let libraryDirectory = ProjectConvention.path(
            directory,
            ProjectConvention.libraryDirectory
        )
        let libraryNames = files.keys
            .filter { (($0 as NSString).deletingLastPathComponent) == libraryDirectory }
            .map { ($0 as NSString).lastPathComponent }

        // One level below the project directory: a directory holding an
        // `arch` directory is a split system.
        var subdirectories: [String: [String: [String]]] = [:]
        for path in files.keys {
            let kindDirectory = (path as NSString).deletingLastPathComponent
            let subproject = (kindDirectory as NSString).deletingLastPathComponent
            guard (subproject as NSString).deletingLastPathComponent == directory else { continue }

            let name = (subproject as NSString).lastPathComponent
            guard name != ProjectConvention.libraryDirectory else { continue }
            let kind = (kindDirectory as NSString).lastPathComponent
            subdirectories[name, default: [:]][kind, default: []]
                .append((path as NSString).lastPathComponent)
        }
        subdirectories = subdirectories.filter {
            $0.value[ProjectConvention.architectureExtension]?.isEmpty == false
        }

        return ProjectLayout(
            root: root,
            directory: directory,
            systems: ProjectConvention.systems(
                in: directory,
                fileNames: names,
                subdirectories: subdirectories
            ),
            libraryPaths: ProjectConvention.libraries(
                in: libraryDirectory,
                fileNames: libraryNames
            )
        )
    }

    public func read(path: String) throws -> String {
        guard let text = files[path] else {
            throw ProjectError.cannotRead(path: path, reason: "there is no such file")
        }
        return text
    }

    public func write(_ text: String, to path: String) throws {
        writeCounts[path, default: 0] += 1
        put(text, at: path)
    }

    /// A picture is bytes. This holds it as the text of its own byte count, so
    /// a test can say a file was written without holding a bitmap.
    public func write(bytes: Data, to path: String) throws {
        writeCounts[path, default: 0] += 1
        put("<\(bytes.count) bytes>", at: path)
    }

    /// How many times a save wrote this path, for a test that states which
    /// files a save touched.
    public func writeCount(at path: String) -> Int { writeCounts[path] ?? 0 }

    /// How many writes every path saw together, for a test that states a
    /// save wrote no file at all.
    public var totalWriteCount: Int { writeCounts.values.reduce(0, +) }

    /// Clears the write counts, so a test can isolate the writes one save
    /// makes from the writes before it.
    public func resetWriteCounts() { writeCounts = [:] }

    public func delete(path: String) throws {
        files.removeValue(forKey: path)
    }

    public func exists(path: String) -> Bool {
        files[path] != nil || directories.contains(path)
    }
}
