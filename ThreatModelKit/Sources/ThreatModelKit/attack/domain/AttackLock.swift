import Foundation

/// What the project records about the ATT&CK data its team agreed on.
///
/// The lock file is the project's and the data is the machine's: a team
/// commits the tag and the checksums, and every machine synchronises the same
/// release. The file never holds the data.
public struct AttackLock: Equatable, Sendable {
    public static let fileName = "mitre.lock.json"

    public let repository: String
    public let tag: String
    /// The bundle the two files were extracted from.
    public let bundle: String
    /// The `sha256` of each written file, by file name.
    public let files: [String: String]

    public init(repository: String, tag: String, bundle: String, files: [String: String]) {
        self.repository = repository
        self.tag = tag
        self.bundle = bundle
        self.files = files
    }

    private struct Document: Codable, Equatable {
        let repository: String
        let tag: String
        let bundle: String
        let files: [String: String]
    }

    /// The lock file a project holds, or nil when it holds none.
    public static func read(_ text: String) -> AttackLock? {
        guard let data = text.data(using: .utf8),
              let document = try? JSONDecoder().decode(Document.self, from: data) else {
            return nil
        }
        return AttackLock(
            repository: document.repository,
            tag: document.tag,
            bundle: document.bundle,
            files: document.files
        )
    }

    /// The file, pretty-printed with sorted keys, so a diff of one line is one
    /// line.
    public var text: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let document = Document(
            repository: repository,
            tag: tag,
            bundle: bundle,
            files: files
        )
        guard let data = try? encoder.encode(document),
              let text = String(data: data, encoding: .utf8) else {
            return "{}\n"
        }
        return text + "\n"
    }

    /// The `sha256` of a file's bytes, the way the library lock states it.
    public static func checksum(_ text: String) -> String {
        LibraryLock.checksum(text)
    }
}
