import Foundation
import ThreatModelKit

/// An index a test fills by hand, so no test runs `git` or reaches a server.
public final class FakeLibraryIndex: LibraryIndexFetching, @unchecked Sendable {
    private let lock = NSLock()
    private var textByRepository: [String: String] = [:]
    private var faultByRepository: [String: LibraryFetchFault] = [:]
    private var readsValue: [String] = []

    public init() {}

    /// Every repository this index was asked for, in order. A test states
    /// that nothing reads an index until a person asks.
    public var reads: [String] {
        lock.lock()
        defer { lock.unlock() }
        return readsValue
    }

    public func put(_ text: String, at repository: String) {
        lock.lock()
        defer { lock.unlock() }
        textByRepository[repository] = text
    }

    /// What this index throws for one repository, for the machine with no
    /// network.
    public func refuse(_ fault: LibraryFetchFault, at repository: String) {
        lock.lock()
        defer { lock.unlock() }
        faultByRepository[repository] = fault
    }

    public func fetchIndex(repository: String) throws -> String {
        lock.lock()
        readsValue.append(repository)
        let fault = faultByRepository[repository]
        let text = textByRepository[repository]
        lock.unlock()

        if let fault { throw fault }
        guard let text else {
            throw LibraryFetchFault.cannotRead(
                reason: "that repository holds no \(LibraryIndex.fileName) at its root"
            )
        }
        return text
    }
}
