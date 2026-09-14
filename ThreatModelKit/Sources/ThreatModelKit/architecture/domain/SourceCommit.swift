import Foundation

/// One commit of the project, as the history reads it.
public struct SourceCommit: Equatable, Sendable {
    /// The full hash, which `git show` takes.
    public let hash: String
    /// The first seven characters, which a person reads.
    public let shortHash: String
    public let author: String
    public let date: Date
    public let subject: String

    public init(hash: String, shortHash: String? = nil, author: String, date: Date, subject: String = "") {
        self.hash = hash
        self.shortHash = shortHash ?? String(hash.prefix(7))
        self.author = author
        self.date = date
        self.subject = subject
    }
}
