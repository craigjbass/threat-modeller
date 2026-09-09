import Foundation
import Observation
import ThreatModelKit

/// Holds which project is open, which system is drawn, and what the last read
/// said about the files.
///
/// It owns no rules. Every answer comes from a use case.
@MainActor
@Observable
final class ProjectSession {
    private let useCases: UseCaseFactory
    private let watcher: ProjectWatching
    private let defaults: UserDefaults
    private let coalescer: ChangeCoalescing

    private(set) var root: String?
    private(set) var directory: String?
    private(set) var systems: [String] = []
    private(set) var chosenSystem: String?
    /// What the last read of a file said. Errors stop a system being drawn;
    /// warnings do not.
    private(set) var diagnostics: [Diagnostic] = []
    /// The file the diagnostics belong to, for the sheet's heading.
    private(set) var diagnosticsFileName: String?
    private(set) var errorMessage: String?
    /// How many threats the last save left with no answer.
    private(set) var unansweredThreats = 0
    /// Where the last report was written.
    private(set) var reportPath: String?

    /// The session drawing the chosen system, or nil while nothing is drawn.
    private(set) var model: ThreatModelSession?
    /// What the last save or compile did, for the bar above the diagram.
    private(set) var lastActionMessage: String?
    /// True when a file changed on disk and this session did not reload,
    /// because something on screen is unsaved.
    private(set) var hasFilesChangedOnDisk = false

    /// The numbers the last read or write of the source files answered.
    private var fingerprint: [String: Int] = [:]
    /// The revision the drawn model had when this session last read or wrote
    /// the files.
    private var savedRevision = 0

    init(
        useCases: UseCaseFactory,
        watcher: ProjectWatching = FSEventsProjectWatcher(),
        defaults: UserDefaults = .standard,
        coalescer: ChangeCoalescing = TimerCoalescer()
    ) {
        self.useCases = useCases
        self.watcher = watcher
        self.defaults = defaults
        self.coalescer = coalescer
        if defaults.object(forKey: Self.autoSyncKey) == nil {
            defaults.set(true, forKey: Self.autoSyncKey)
        }
        isAutoSyncOn = defaults.bool(forKey: Self.autoSyncKey)
    }

    private static let autoSyncKey = "autoSync"

    /// True while this application redraws the project on its own when a file
    /// changes on disk. It starts on, and the user turns it off in the
    /// workflow bar. The choice outlives the run.
    var isAutoSyncOn: Bool = true {
        didSet {
            defaults.set(isAutoSyncOn, forKey: Self.autoSyncKey)
            // Turning it off drops the write that is waiting, because the user
            // has just said this application must not write on its own.
            if isAutoSyncOn == false { coalescer.cancel() }
            // Turning it on answers the change the user has been looking at.
            if isAutoSyncOn, hasFilesChangedOnDisk, hasUnsavedChanges == false {
                reloadFromDisk()
            }
        }
    }

    var hasErrors: Bool {
        diagnostics.contains { $0.severity == .error }
    }

    /// True when the drawn model holds a change no file holds.
    var hasUnsavedChanges: Bool {
        guard let model else { return false }
        return model.revision > savedRevision
    }

    /// True when the open root holds no system, so this application can offer
    /// to write one.
    var canInitialise: Bool {
        root != nil && systems.isEmpty
    }

    /// The examples this application can write into an empty project.
    var examples: [ListedSample] {
        useCases.listSampleModels().execute(ListSampleModelsRequest()).samples
    }

    /// Writes one example into the open root, and draws it.
    ///
    /// It never writes over a system, so a root that already holds one says so
    /// and changes nothing.
    func initialise(sampleId: String? = nil) {
        guard let root else { return }

        switch useCases.initialiseProject().execute(
            InitialiseProjectRequest(root: root, sampleId: sampleId)
        ) {
        case .created:
            errorMessage = nil
            open(root: root)
        case .alreadyHasSystems(let names):
            // Reading the project again is what puts those systems on screen,
            // and it clears the message, so the message comes after it.
            open(root: root)
            errorMessage = "This project already holds \(names.joined(separator: ", "))." 
        case .noSuchSample:
            errorMessage = "This application no longer holds that example."
        case .notAProject(let reason):
            errorMessage = "That is not a project: \(reason)"
        case .cannotWrite(let reason):
            errorMessage = "The example could not be written: \(reason)"
        }
    }

    /// Opens a project root and draws one of its systems.
    ///
    /// It draws the system named in `preferring` when the project still holds
    /// it, and the first system when it does not.
    func open(root: String, preferring wanted: String? = nil) {
        // A write waiting for the project being left must not land in it.
        coalescer.cancel()

        switch useCases.openProject().execute(OpenProjectRequest(root: root)) {
        case .opened(let systems, let directory):
            self.root = root
            self.directory = directory
            self.systems = systems
            errorMessage = systems.isEmpty
                ? "\(directory) holds no .arch files. Start from an example, or write one."
                : nil

            // Every system reads every library, so they load before one is
            // drawn. A library that does not load stops the project.
            guard loadLibraries(root: root) else { return }
            fingerprint = currentFingerprint()
            watcher.stop()
            watcher.watch(directory: directory) { [weak self] in self?.filesChanged() }
            let chosen = systems.contains(wanted ?? "") ? wanted : systems.first
            if let chosen { choose(chosen) }
        case .notAProject(let reason):
            self.root = nil
            systems = []
            model = nil
            watcher.stop()
            errorMessage = "That is not a project: \(reason)"
        }
    }

    /// Reads the project's libraries into the catalogue every later use case
    /// reads. It answers false when one did not load, and says which file.
    private func loadLibraries(root: String) -> Bool {
        switch useCases.loadLibraries().execute(LoadLibrariesRequest(root: root)) {
        case .loaded(let libraries, let warnings):
            useCases.useLibraries(libraries)
            diagnostics = warnings
            diagnosticsFileName = warnings.isEmpty ? nil : "a library"
            return true
        case .refused(let fileName, let faults):
            useCases.useLibraries([])
            model = nil
            chosenSystem = nil
            diagnostics = faults
            diagnosticsFileName = fileName
            errorMessage = "\(fileName) did not parse."
            return false
        case .notAProject(let reason):
            useCases.useLibraries([])
            model = nil
            errorMessage = "That is not a project: \(reason)"
            return false
        }
    }

    /// Reads the files again and draws them. It keeps the chosen system when
    /// the project still holds it.
    func reloadFromDisk() {
        guard let root else { return }
        hasFilesChangedOnDisk = false
        open(root: root, preferring: chosenSystem)
    }

    /// Leaves what is on screen alone. The notice returns when a file changes
    /// again.
    func keepMine() {
        hasFilesChangedOnDisk = false
        fingerprint = currentFingerprint()
    }

    /// What the watcher calls. A change this application wrote itself answers
    /// the same fingerprint, so nothing happens.
    ///
    /// It redraws only when auto sync is on and nothing on screen is unsaved.
    /// In every other case it raises the notice and the user picks.
    private func filesChanged() {
        let current = currentFingerprint()
        guard current != fingerprint else { return }

        if isAutoSyncOn && hasUnsavedChanges == false {
            reloadFromDisk()
        } else {
            hasFilesChangedOnDisk = true
        }
    }

    private func currentFingerprint() -> [String: Int] {
        guard let root else { return [:] }
        switch useCases.readProjectFingerprint().execute(
            ReadProjectFingerprintRequest(root: root)
        ) {
        case .read(let fingerprint): return fingerprint
        case .notAProject: return [:]
        }
    }

    /// Draws one system. A file with a fault draws nothing and fills the
    /// diagnostics, because half a diagram is worse than none.
    func choose(_ systemName: String) {
        guard let root else { return }
        // The same rule as `open`: the write belongs to the system being left.
        coalescer.cancel()

        switch useCases.openSystem().execute(
            OpenSystemRequest(root: root, systemName: systemName)
        ) {
        case .opened(_, let warnings):
            chosenSystem = systemName
            diagnostics = warnings
            diagnosticsFileName = "\(systemName).arch"
            errorMessage = nil
            lastActionMessage = nil
            let drawn = ThreatModelSession(useCases: useCases)
            model = drawn
            savedRevision = drawn.revision
            hasFilesChangedOnDisk = false
            // Set last, so building the session does not count as a change.
            drawn.onChange = { [weak self] in self?.modelDidChange() }
        case .refused(let fileName, let faults):
            chosenSystem = systemName
            diagnostics = faults
            diagnosticsFileName = fileName
            model = nil
            lastActionMessage = nil
            savedRevision = 0
            hasFilesChangedOnDisk = false
            errorMessage = "\(fileName) did not parse."
        case .noSuchSystem:
            errorMessage = "This project no longer holds \"\(systemName)\"."
        case .cannotRead(let reason):
            errorMessage = "That system could not be read: \(reason)"
        }
    }

    /// What the window calls when the drawn model changed.
    ///
    /// With auto sync on, a change on screen reaches the files without the
    /// user pressing Synchronise. The write waits for the changes to stop, so
    /// a name typed into a field writes the files once and not once a letter.
    func modelDidChange() {
        guard isAutoSyncOn, hasUnsavedChanges else { return }
        coalescer.schedule { [weak self] in self?.save() }
    }

    /// Writes the drawn system back to the file it came from, and merges the
    /// answers on screen into its controls file.
    func save() {
        guard let root, let chosenSystem else { return }

        switch useCases.saveSystem().execute(
            SaveSystemRequest(root: root, systemName: chosenSystem)
        ) {
        case .saved:
            errorMessage = nil
            saveAnswers(root: root, systemName: chosenSystem)
            savedRevision = model?.revision ?? 0
            fingerprint = currentFingerprint()
            hasFilesChangedOnDisk = false
        case .noSuchSystem:
            errorMessage = "This project no longer holds \"\(chosenSystem)\"."
        case .cannotWrite(let reason):
            errorMessage = "That system could not be written: \(reason)"
        }
    }

    private func saveAnswers(root: String, systemName: String) {
        switch useCases.saveSystemAnswers().execute(
            SaveSystemAnswersRequest(root: root, systemName: systemName)
        ) {
        case .saved(_, _, let unanswered, _):
            unansweredThreats = unanswered
            lastActionMessage = unanswered == 0
                ? "Saved."
                : "Saved. \(unanswered) threats have no answer."
        case .noSuchSystem:
            errorMessage = "This project no longer holds \"\(systemName)\"."
        case .refused(let faults):
            diagnostics = faults
            diagnosticsFileName = "\(systemName).controls"
            errorMessage = "\(systemName).controls did not parse."
        case .cannotWrite(let reason):
            errorMessage = "The answers could not be written: \(reason)"
        }
    }

    /// Writes the Markdown report for the drawn system.
    func compileReport() {
        guard let root, let chosenSystem else { return }

        switch useCases.compileSystemReport().execute(
            CompileSystemReportRequest(root: root, systemName: chosenSystem)
        ) {
        case .written(let path):
            errorMessage = nil
            reportPath = path
            lastActionMessage = "Report: \(path)"
        case .noSuchSystem:
            errorMessage = "This project no longer holds \"\(chosenSystem)\"."
        case .cannotWrite(let reason):
            errorMessage = "The report could not be written: \(reason)"
        }
    }

    func dismissDiagnostics() {
        diagnostics = []
    }
}
