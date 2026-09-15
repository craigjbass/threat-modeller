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
/// The index is read only when a person asks, never at launch. Reading one
/// runs `git` over the index repository and reads one file from it; nothing
/// in an index is executed.
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
            return .cannotRead(reason: fault.message)
        } catch {
            return .cannotRead(reason: String(describing: error))
        }
    }
}
