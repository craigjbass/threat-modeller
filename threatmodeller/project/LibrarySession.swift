import Observation
import ThreatModelKit

/// One row of the Libraries sheet.
///
/// It joins what `ListLibraries` says with what `ListOutdatedLibraries` says,
/// because neither use case holds both and the sheet shows one line.
struct LibraryRow: Equatable, Identifiable, Sendable {
    var id: String { label }
    let label: String
    let name: String
    let repository: String
    let tag: String
    let matchesLock: Bool
    /// The newest tag the repository holds, once a person asked. Nil means the
    /// recorded tag is the newest, or nobody has asked.
    var newestTag: String?
    /// Why the tags could not be read, or nil.
    var reason: String?
}

/// Holds what the Libraries sheet shows, and what its buttons do.
///
/// It owns no rule. Every answer comes from a use case, and each one is the use
/// case the matching `threatmodeller library` verb calls, so the window and the
/// executable cannot disagree about what `add` means.
@MainActor
@Observable
final class LibrarySession {
    private let useCases: UseCaseFactory
    private let root: String
    /// What the project window does after a change, so the palette shows a
    /// library that has just arrived.
    private let onChange: () -> Void

    private(set) var libraries: [LibraryRow] = []
    private(set) var errorMessage: String?
    /// True while a fetch runs. The buttons are off while it is true.
    private(set) var isWorking = false
    /// The systems that still name a library a user asked to remove, so the
    /// sheet can ask again. Nil means nothing is waiting on an answer.
    private(set) var removalInUse: [String]?

    init(useCases: UseCaseFactory, root: String, onChange: @escaping () -> Void) {
        self.useCases = useCases
        self.root = root
        self.onChange = onChange
        reload()
    }

    /// Reads the lock file and the files on disk. It reaches no server, so the
    /// sheet opens without a fetch.
    func reload() {
        switch useCases.listLibraries().execute(ListLibrariesRequest(root: root)) {
        case .listed(let listed):
            let newestByLabel = Dictionary(
                libraries.map { ($0.label, ($0.newestTag, $0.reason)) },
                uniquingKeysWith: { first, _ in first }
            )
            libraries = listed.map { one in
                LibraryRow(
                    label: one.label,
                    name: one.name,
                    repository: one.repository,
                    tag: one.tag,
                    matchesLock: one.matchesLock,
                    newestTag: newestByLabel[one.label]?.0,
                    reason: newestByLabel[one.label]?.1
                )
            }
        case .notAProject(let reason):
            libraries = []
            errorMessage = "That is not a project: \(reason)"
        }
    }

    func add(repository: String, tag: String) async {
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }

        switch useCases.addLibrary().execute(
            AddLibraryRequest(root: root, repository: repository, tag: tag)
        ) {
        case .added:
            reload()
            onChange()
        case .cannotFetch(let reason), .refused(let reason),
             .notAProject(let reason), .cannotWrite(let reason):
            errorMessage = reason
        }
    }

    func update(label: String?) async {
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }

        switch useCases.updateLibraries().execute(
            UpdateLibrariesRequest(root: root, label: label)
        ) {
        case .updated:
            reload()
            onChange()
        case .noSuchLibrary:
            errorMessage = "This project no longer holds that library."
        case .cannotFetch(let label, let reason), .refused(let label, let reason):
            errorMessage = "\(label): \(reason)"
        case .notAProject(let reason):
            errorMessage = "That is not a project: \(reason)"
        }
    }

    /// Removes a library. It refuses the first time while a system names one of
    /// the library's technologies, and fills `removalInUse` so the sheet can
    /// ask again.
    func remove(label: String, isForced: Bool) {
        errorMessage = nil
        removalInUse = nil

        switch useCases.removeLibrary().execute(
            RemoveLibraryRequest(root: root, label: label, isForced: isForced)
        ) {
        case .removed:
            reload()
            onChange()
        case .inUse(let systems):
            removalInUse = systems
        case .noSuchLibrary:
            errorMessage = "This project no longer holds that library."
        case .notAProject(let reason), .cannotWrite(let reason):
            errorMessage = reason
        }
    }

    /// Reads each repository's tags. This is the one thing in the sheet that
    /// reaches a server without being asked for a change, so a person presses
    /// it rather than the window running it on its own.
    func checkForUpdates() async {
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }

        guard case .listed(let outdated) = useCases.listOutdatedLibraries().execute(
            ListOutdatedLibrariesRequest(root: root)
        ) else {
            errorMessage = "The tags could not be read."
            return
        }

        let byLabel = Dictionary(
            outdated.map { ($0.label, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        libraries = libraries.map { row in
            var updated = row
            updated.newestTag = byLabel[row.label]?.newestTag
            updated.reason = byLabel[row.label]?.reason
            return updated
        }
    }

    /// The user answered the question `removalInUse` asked.
    func cancelRemoval() {
        removalInUse = nil
    }
}
