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

    /// The tags one repository holds, without a file for each. A test about
    /// which tag is newest states the tags and nothing else.
    public func hold(tags: [String], at repository: String) {
        lock.lock()
        defer { lock.unlock() }
        tagsByRepository[repository] = tags
    }

    /// How long a fetch waits before it answers, so a test can press Cancel
    /// while one is in flight. Zero means it answers at once.
    ///
    /// A test writes it on one thread and `fetch` reads it on another, so the
    /// lock carries it across. Reading it without the lock let a fetch see
    /// zero, answer at once, and finish before Cancel arrived.
    public var waits: TimeInterval {
        get {
            lock.lock()
            defer { lock.unlock() }
            return waitsValue
        }
        set {
            lock.lock()
            waitsValue = newValue
            lock.unlock()
        }
    }

    private var waitsValue: TimeInterval = 0

    /// Stops a fetch that is waiting. The waiting fetch then throws.
    public func cancel() {
        lock.lock()
        isCancelled = true
        cancelsValue += 1
        lock.unlock()
    }

    /// How many times something pressed Cancel. Read on the main thread while
    /// a fetch runs on another, so the lock carries it too.
    public var cancels: Int {
        lock.lock()
        defer { lock.unlock() }
        return cancelsValue
    }

    private var cancelsValue = 0
    private var isCancelled = false

    public func fetch(repository: String, tag: String) throws -> [String: String] {
        if repository.hasPrefix("-") { throw LibraryFetchFault.badRepository(repository) }

        let waitsFor = waits
        if waitsFor > 0 {
            let until = Date().addingTimeInterval(waitsFor)
            while Date() < until {
                lock.lock()
                let stopped = isCancelled
                lock.unlock()
                if stopped { throw LibraryFetchFault.cancelled }
                Thread.sleep(forTimeInterval: 0.005)
            }
        }
        lock.lock()
        if isCancelled {
            isCancelled = false
            lock.unlock()
            throw LibraryFetchFault.cancelled
        }
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
        tagReads += 1
        return tagsByRepository[repository] ?? []
    }

    /// The newest tag, the way a repository that can sort answers: one tag,
    /// and the whole list is never handed back.
    public func newestTag(repository: String, wantsPreRelease: Bool) throws -> String? {
        if repository.hasPrefix("-") { throw LibraryFetchFault.badRepository(repository) }
        lock.lock()
        let held = tagsByRepository[repository] ?? []
        newestTagReads += 1
        lock.unlock()
        return TagVersion.newest(of: held, wantsPreRelease: wantsPreRelease)
    }

    /// How many times something read every tag of a repository, and how many
    /// times something asked for the newest one. A test states which call the
    /// use case makes.
    public var tagReads = 0
    public var newestTagReads = 0
}
