import Foundation
import ThreatModelKit

/// A fetcher a test fills by hand, so no test runs `git` or reaches a server.
public final class FakeLibraryFetcher: LibraryFetching, @unchecked Sendable {
    private let lock = NSLock()
    private var filesByTag: [String: [String: String]] = [:]
    private var tagsByRepository: [String: [String]] = [:]
    private var fetchedValue: [String] = []

    public init() {}

    /// Every `<repository>@<tag>` this fetcher was asked for, in order.
    public var fetched: [String] {
        lock.lock()
        defer { lock.unlock() }
        return fetchedValue
    }

    /// What `fetch` answers for one repository and tag.
    public func put(_ files: [String: String], repository: String, tag: String) {
        lock.lock()
        defer { lock.unlock() }
        filesByTag["\(repository)@\(tag)"] = files
        if tagsByRepository[repository]?.contains(tag) != true {
            tagsByRepository[repository, default: []].append(tag)
        }
    }

    public func fetch(repository: String, tag: String) throws -> [String: String] {
        if repository.hasPrefix("-") { throw LibraryFetchFault.badRepository(repository) }
        lock.lock()
        defer { lock.unlock() }
        fetchedValue.append("\(repository)@\(tag)")
        guard let files = filesByTag["\(repository)@\(tag)"] else {
            throw LibraryFetchFault.cannotRead(
                reason: "fatal: Remote branch \(tag) not found in upstream origin"
            )
        }
        guard files.isEmpty == false else { throw LibraryFetchFault.noLibraryFile }
        return files
    }

    public func tags(repository: String) throws -> [String] {
        if repository.hasPrefix("-") { throw LibraryFetchFault.badRepository(repository) }
        lock.lock()
        defer { lock.unlock() }
        return tagsByRepository[repository] ?? []
    }
}
