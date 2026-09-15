import Foundation

/// One library an index lists.
public struct IndexedLibrary: Equatable, Sendable {
    public let label: String
    public let name: String
    public let description: String
    public let repository: String
    /// The tags the entry states, newest first. Empty means the entry states
    /// none and a person types the tag.
    public let tags: [String]
    public let homepage: String?

    public init(
        label: String,
        name: String,
        description: String = "",
        repository: String,
        tags: [String] = [],
        homepage: String? = nil
    ) {
        self.label = label
        self.name = name
        self.description = description
        self.repository = repository
        self.tags = tags
        self.homepage = homepage
    }

    /// The tag *Add* offers, or nil when the entry states none.
    public var newestTag: String? {
        TagVersion.newest(of: tags) ?? tags.first
    }
}

/// The file an index repository holds.
public enum LibraryIndex {
    /// The format version this application reads.
    public static let version = 1
    /// The file an index repository holds at its root.
    public static let fileName = "index.json"

    public enum Fault: Error, Equatable, Sendable {
        case notJson
        case unsupportedVersion(found: Int)

        public var message: String {
            switch self {
            case .notJson:
                "that repository's \(LibraryIndex.fileName) is not an index this application reads"
            case .unsupportedVersion(let found):
                "that index states version \(found), and this application reads version "
                    + "\(LibraryIndex.version)"
            }
        }
    }

    /// What the index holds, in the order it states them.
    public static func read(_ text: String) throws -> [IndexedLibrary] {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw Fault.notJson
        }
        let version = json["version"] as? Int ?? 0
        guard version == Self.version else { throw Fault.unsupportedVersion(found: version) }

        let rows = json["libraries"] as? [[String: Any]] ?? []
        return rows.compactMap { row in
            guard let label = row["label"] as? String,
                  let name = row["name"] as? String,
                  let repository = row["repository"] as? String else { return nil }
            return IndexedLibrary(
                label: label,
                name: name,
                description: row["description"] as? String ?? "",
                repository: repository,
                tags: row["tags"] as? [String] ?? [],
                homepage: row["homepage"] as? String
            )
        }
    }

    /// The entries whose name, label or description hold the words a person
    /// typed. Empty words give the whole index.
    public static func narrow(_ libraries: [IndexedLibrary], to words: String) -> [IndexedLibrary] {
        let wanted = words.trimmingCharacters(in: .whitespaces).lowercased()
        guard wanted.isEmpty == false else { return libraries }
        return libraries.filter {
            $0.name.lowercased().contains(wanted)
                || $0.label.lowercased().contains(wanted)
                || $0.description.lowercased().contains(wanted)
        }
    }
}
