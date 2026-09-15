import Foundation

/// One project root the user opened before.
struct RecentProject: Identifiable, Equatable {
    /// The path, which is unique in the list.
    var id: String { path }
    let path: String
    /// The last part of the path, which is what the welcome window shows.
    let name: String
}

/// Remembers the project roots the user opened.
///
/// The application is not sandboxed, so a path is the whole entry. An entry a
/// sandboxed version wrote carried a bookmark beside the path; that bookmark is
/// ignored and the path is read, so an older list still opens.
@MainActor
final class RecentProjects {
    private let defaults: UserDefaults
    private static let key = "recentProjects"
    private static let limit = 10

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// Puts a root at the top of the list. A root already in the list moves to
    /// the top rather than appearing twice.
    func record(url: URL) {
        var rows = storedRows().filter { $0["path"] as? String != url.path }
        rows.insert(["path": url.path], at: 0)
        defaults.set(Array(rows.prefix(Self.limit)), forKey: Self.key)
    }

    /// Newest first, at most ten.
    func list() -> [RecentProject] {
        storedRows().compactMap { row in
            guard let path = row["path"] as? String else { return nil }
            return RecentProject(path: path, name: (path as NSString).lastPathComponent)
        }
    }

    /// Answers the root this entry names, or nil when the directory is no
    /// longer there. An entry that no longer resolves is dropped from the list.
    func resolve(_ entry: RecentProject) -> URL? {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: entry.path, isDirectory: &isDirectory),
              isDirectory.boolValue else {
            forget(path: entry.path)
            return nil
        }
        return URL(fileURLWithPath: entry.path, isDirectory: true)
    }

    /// True when the directory this entry names is still there. It forgets
    /// nothing: the menu dims a row it cannot open, and drops it on the next
    /// record.
    func exists(_ entry: RecentProject) -> Bool {
        var isDirectory: ObjCBool = false
        return FileManager.default.fileExists(atPath: entry.path, isDirectory: &isDirectory)
            && isDirectory.boolValue
    }

    /// The project the application would reopen at launch, or nil when the
    /// list is empty.
    func mostRecent() -> RecentProject? { list().first }

    /// Empties the list. The Clear Menu item calls it.
    func clear() {
        defaults.removeObject(forKey: Self.key)
    }

    private func forget(path: String) {
        defaults.set(storedRows().filter { $0["path"] as? String != path }, forKey: Self.key)
    }

    private func storedRows() -> [[String: Any]] {
        defaults.array(forKey: Self.key) as? [[String: Any]] ?? []
    }
}
