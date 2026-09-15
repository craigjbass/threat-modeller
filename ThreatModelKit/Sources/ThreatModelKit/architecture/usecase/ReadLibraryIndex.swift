public protocol ReadLibraryIndexUseCase {
    func execute(_ request: ReadLibraryIndexRequest) -> ReadLibraryIndexResponse
}

public struct ReadLibraryIndexRequest: Equatable, Sendable {
    /// The index repository. Nil reads the one this application ships with.
    public let repository: String?

    public init(repository: String? = nil) {
        self.repository = repository
    }
}

public enum ReadLibraryIndexResponse: Equatable, Sendable {
    case read(libraries: [IndexedLibrary])
    /// The index could not be read: no network, no access, or no such file.
    case cannotRead(reason: String)
}

/// Lists the libraries an index holds.
///
/// The index is read only when a person asks, never at launch. A public
/// index is one file behind a plain address and is read plainly; anything
/// else is read with `git`, which uses the access a person already has.
/// Nothing in an index is executed.
public struct ReadLibraryIndex: ReadLibraryIndexUseCase {
    private let indexes: LibraryIndexFetching

    public init(indexes: LibraryIndexFetching) {
        self.indexes = indexes
    }

    public func execute(_ request: ReadLibraryIndexRequest) -> ReadLibraryIndexResponse {
        let repository = request.repository ?? ProjectConvention.defaultLibraryIndex
        do {
            return .read(libraries: try LibraryIndex.read(
                try indexes.fetchIndex(repository: repository)
            ))
        } catch let fault as LibraryIndex.Fault {
            return .cannotRead(reason: fault.message)
        } catch let fault as LibraryFetchFault {
            return .cannotRead(reason: Self.said(fault.message, of: repository))
        } catch {
            return .cannotRead(reason: Self.said(String(describing: error), of: repository))
        }
    }

    /// What a person reads when the index does not answer.
    ///
    /// A tool's own words say what failed and not what to do about it, so the
    /// address and the two things a person can check go in front of them.
    static func said(_ reason: String, of repository: String) -> String {
        "The index at \(repository) could not be read. Check that the address is "
            + "right and that this machine reaches it. What answered: \(reason)"
    }
}
