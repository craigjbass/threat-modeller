import Foundation

/// One project root the user opened before.
struct RecentProject: Identifiable, Equatable {
    /// The path, which is unique in the list.
    var id: String { path }
    let path: String
    /// The last part of the path, which is what the welcome window shows.
    let name: String
    /// The bookmark that reopens the root without an open panel.
    let bookmark: Data
}

/// Remembers the project roots the user opened.
///
/// The application is sandboxed, so a path alone cannot be opened again after
/// a relaunch. Each entry keeps an app-scoped bookmark, which
/// `threatmodeller.entitlements` grants.
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
        guard let bookmark = try? url.bookmarkData(
            options: .withSecurityScope,
            includingResourceValuesForKeys: nil,
            relativeTo: nil
        ) else { return }

        var rows = storedRows().filter { $0["path"] as? String != url.path }
        rows.insert(["path": url.path, "bookmark": bookmark], at: 0)
        defaults.set(Array(rows.prefix(Self.limit)), forKey: Self.key)
    }

    /// Newest first, at most ten.
    func list() -> [RecentProject] {
        storedRows().compactMap { row in
            guard let path = row["path"] as? String,
                  let bookmark = row["bookmark"] as? Data else { return nil }
            return RecentProject(
                path: path,
                name: (path as NSString).lastPathComponent,
                bookmark: bookmark
            )
        }
    }

    /// Answers the root this entry names, or nil when the bookmark no longer
    /// resolves. A stale entry is dropped from the list.
    func resolve(_ entry: RecentProject) -> URL? {
        var isStale = false
        guard let url = try? URL(
            resolvingBookmarkData: entry.bookmark,
            options: .withSecurityScope,
            relativeTo: nil,
            bookmarkDataIsStale: &isStale
        ), isStale == false else {
            forget(path: entry.path)
            return nil
        }
        return url
    }

    private func forget(path: String) {
        defaults.set(storedRows().filter { $0["path"] as? String != path }, forKey: Self.key)
    }

    private func storedRows() -> [[String: Any]] {
        defaults.array(forKey: Self.key) as? [[String: Any]] ?? []
    }
}
