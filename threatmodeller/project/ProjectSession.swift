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
    /// The composition root this session runs on. The project window reads it
    /// to build the Libraries sheet's own session over the same root.
    let useCases: UseCaseFactory
    private let watcher: ProjectWatching
    private let defaults: UserDefaults
    private let coalescer: ChangeCoalescing
    /// Waits out `messageDuration` and then clears the message. A test gives
    /// its own, runs the work at once, and never waits.
    private let messageTimer: ChangeCoalescing
    /// What opens the report in another application.
    private let workspace: Workspace

    private(set) var root: String?
    private(set) var directory: String?
    private(set) var systems: [String] = []
    private(set) var chosenSystem: String?
    /// What the last read of a file said. Errors stop a system being drawn;
    /// warnings do not.
    private(set) var diagnostics: [Diagnostic] = []
    /// The file the diagnostics belong to, for the sheet's heading.
    private(set) var diagnosticsFileName: String?
    /// Where that file is, or nil when the faults belong to no one file. A row
    /// in the sheet opens the file, so it needs the path and not the name.
    var diagnosticsPath: String? {
        guard let directory, let diagnosticsFileName,
              diagnosticsFileName.contains(".") else { return nil }
        return "\(directory)/\(diagnosticsFileName)"
    }
    private(set) var errorMessage: String?
    /// How many threats the last save left with no answer.
    private(set) var unansweredThreats = 0
    /// Where the last report was written.
    private(set) var reportPath: String?
    /// The tag the open system's file states against the tag in use, when the
    /// two differ and the person has not said to keep the one the file states.
    private(set) var catalogueDrift: CatalogueDrift?

    /// The session drawing the chosen system, or nil while nothing is drawn.
    private(set) var model: ThreatModelSession?

    /// What a load is doing, or nil when nothing is loading. The window says
    /// this, because opening a large model takes long enough that a still
    /// window reads as a broken one.
    private(set) var loading: LoadingStage?

    /// True while a write is in flight. The bar says so, because a write
    /// re-imports the architecture and that is not instant.
    private(set) var isSaving = false

    /// The diagram as the layout search last had it, while a load runs. It
    /// holds geometry and nothing else, because that is all the search knows.
    private(set) var formingDiagram: LayOutModelResponse?

    /// The stages of opening a project, in the order they run.
    enum LoadingStage: String, CaseIterable {
        case readingTheProject
        case loadingLibraries
        case drawingTheSystem
        case scoringTheThreats

        /// What to say about this stage, to a person.
        var says: String {
            switch self {
            case .readingTheProject: "Reading the project\u{2026}"
            case .loadingLibraries: "Loading the libraries\u{2026}"
            case .drawingTheSystem: "Laying the diagram out\u{2026}"
            case .scoringTheThreats: "Scoring the threats\u{2026}"
            }
        }
    }
    /// What the last save or compile did, for the toolbar. It clears itself
    /// after `messageDuration`, so the window never says "Saved." over a model
    /// the person has changed since.
    private(set) var lastActionMessage: String?
    /// How long a save or report message stays on screen.
    static let messageDuration = 4.0
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
        coalescer: ChangeCoalescing = TimerCoalescer(),
        messageTimer: ChangeCoalescing = TimerCoalescer(wait: ProjectSession.messageDuration),
        workspace: Workspace = SystemWorkspace()
    ) {
        self.workspace = workspace
        self.useCases = useCases
        self.watcher = watcher
        self.defaults = defaults
        self.coalescer = coalescer
        self.messageTimer = messageTimer
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
                reload()
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

    /// The name to offer for a new system: the project folder's own name.
    /// Typing the folder name again is work nobody needs, and the folder is
    /// usually what the system is called.
    var suggestedSystemName: String {
        guard let root else { return "" }
        return (root as NSString).lastPathComponent
    }

    /// Writes one example into the open root, and draws it.
    ///
    /// It never writes over a system, so a root that already holds one says so
    /// and changes nothing.
    func initialise(sampleId: String? = nil) async {
        await start(.example(id: sampleId))
    }

    /// Writes a system with this name and nothing else, and draws it.
    ///
    /// A user who already knows the system they are about to draw does not
    /// want an example to delete first.
    func initialiseEmpty(systemName: String) async {
        await start(.empty(systemName: systemName))
    }

    private func start(_ from: ProjectStart) async {
        guard let root else { return }

        switch useCases.initialiseProject().execute(
            InitialiseProjectRequest(root: root, start: from)
        ) {
        case .created:
            errorMessage = nil
            await open(root: root)
        case .alreadyHasSystems(let names):
            // Reading the project again is what puts those systems on screen,
            // and it clears the message, so the message comes after it.
            await open(root: root)
            errorMessage = "This project already holds \(names.joined(separator: ", "))." 
        case .noSuchSample:
            errorMessage = "This application no longer holds that example."
        case .needsASystemName:
            errorMessage = "Give the system a name."
        case .notAProject(let reason):
            errorMessage = "That is not a project: \(reason)"
        case .cannotWrite(let reason):
            errorMessage = "The system could not be written: \(reason)"
        }
    }

    /// Opens the project that holds a system's file, on that system.
    ///
    /// A user double-clicks a `.arch` or a `.controls` file in Finder. This
    /// application opens projects, not files, so the file names the project
    /// that holds it. Returns false for a file this application does not read,
    /// and changes nothing.
    @discardableResult
    func openSystemFile(at path: String) async -> Bool {
        guard let found = ProjectConvention.system(atPath: path) else { return false }

        await open(root: found.root, preferring: found.systemName)
        return true
    }

    /// Opens a project root and draws one of its systems.
    ///
    /// It draws the system named in `preferring` when the project still holds
    /// it, and the first system when it does not.
    func open(root: String, preferring wanted: String? = nil) async {
        // A write waiting for the project being left must not land in it.
        coalescer.cancel()
        loading = .readingTheProject
        defer { loading = nil }

        switch useCases.openProject().execute(OpenProjectRequest(root: root)) {
        case .opened(let systems, let directory):
            self.root = root
            self.directory = directory
            self.systems = systems
            errorMessage = systems.isEmpty
                ? "\(directory) holds no .arch files. Name a system, or start from an example."
                : nil

            // Every system reads every library, so they load before one is
            // drawn. A library that does not load stops the project.
            loading = .loadingLibraries
            guard loadLibraries(root: root) else { return }
            fingerprint = currentFingerprint()
            watcher.stop()
            watcher.watch(directory: directory) { [weak self] in self?.filesChanged() }
            let chosen = systems.contains(wanted ?? "") ? wanted : systems.first
            if let chosen { await choose(chosen) }
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

    // MARK: answers the architecture no longer raises

    /// The answers in the controls file for threats the architecture stopped
    /// raising. Language guide 5.4: nothing deletes one, a person does, and
    /// `threatmodeller check` exits 1 while one remains.
    ///
    /// It reads the file rather than the model, because a stale answer never
    /// reaches the model.
    var staleAnswers: [StaleAnswer] {
        guard let root, let chosenSystem else { return [] }
        guard case .listed(let answers) = useCases.listStaleAnswers().execute(
            ListStaleAnswersRequest(root: root, systemName: chosenSystem)
        ) else { return [] }
        return answers
    }

    /// Deletes one, because a person decided to, and reads the project again
    /// so the list on screen matches the file.
    func removeStaleAnswer(_ answer: StaleAnswer) async {
        guard let root, let chosenSystem else { return }

        useCases.removeStaleAnswer()
            .execute(
                RemoveStaleAnswerRequest(
                    root: root,
                    systemName: chosenSystem,
                    threatId: answer.threatId,
                    sourceKind: answer.sourceKind,
                    sourceId: answer.sourceId
                )
            )
            .describe(into: &errorMessage)

        fingerprint = currentFingerprint()
    }

    /// Deletes one from somewhere that cannot wait for it.
    func deleteStaleAnswer(_ answer: StaleAnswer) {
        inFlight = Task { await removeStaleAnswer(answer) }
    }

    /// Reads the files again and draws them. It keeps the chosen system when
    /// the project still holds it.
    func reloadFromDisk() async {
        guard let root else { return }
        hasFilesChangedOnDisk = false
        await open(root: root, preferring: chosenSystem)
    }

    /// Reads the files again from somewhere that cannot wait for it.
    func reload() {
        inFlight = Task { await reloadFromDisk() }
    }

    /// Writes an example, or a system with a name and nothing else, from
    /// somewhere that cannot wait for it.
    func startWriting(_ from: ProjectStart) {
        inFlight = Task { await start(from) }
    }

    /// The load in flight, so a caller that has to know when it finished can
    /// wait for it. A test is the only caller that does.
    private var inFlight: Task<Void, Never>?

    /// Waits for the load in flight, if there is one.
    func settle() async {
        await inFlight?.value
    }

    /// Opens a project from somewhere that cannot wait for it: a menu item, a
    /// file the user double-clicked, a watcher saying a file changed. The
    /// window draws the stage this reaches while it runs.
    func reopen(root: String, preferring wanted: String? = nil) {
        inFlight = Task { await open(root: root, preferring: wanted) }
    }

    /// Draws a system from somewhere that cannot wait for it.
    func pick(_ systemName: String) {
        inFlight = Task { await choose(systemName) }
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
            reload()
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
    func choose(_ systemName: String) async {
        guard let root else { return }
        // The same rule as `open`: the write belongs to the system being left.
        coalescer.cancel()
        // Every way out of here says the load has finished. Without this a
        // system picked from the toolbar left a stage behind, and the window
        // drew that stage for good.
        defer { loading = nil }

        // Reading a system parses its file and lays the diagram out, and the
        // layout is most of what opening a model costs. It runs off the main
        // actor so the window keeps answering while it does. The store guards
        // itself with a lock, which is what lets this leave.
        loading = .drawingTheSystem
        formingDiagram = nil
        // The search reports every plan that beats the best so far, from
        // whatever thread it runs on, so each report hops back here.
        useCases.layoutProgress?.listen { [weak self] forming in
            Task { @MainActor in self?.formingDiagram = forming }
        }
        let outcome = await Task.detached { [useCases] in
            useCases.openSystem().execute(
                OpenSystemRequest(root: root, systemName: systemName)
            )
        }.value
        useCases.layoutProgress?.listen(nil)
        formingDiagram = nil

        switch outcome {
        case .opened(_, let warnings, let statedTag):
            chosenSystem = systemName
            diagnostics = warnings
            diagnosticsFileName = "\(systemName).arch"
            errorMessage = nil
            clearMessage()
            loading = .scoringTheThreats
            let drawn = ThreatModelSession(useCases: useCases)
            model = drawn
            savedRevision = drawn.revision
            hasFilesChangedOnDisk = false
            // Set last, so building the session does not count as a change.
            drawn.onChange = { [weak self] in self?.modelDidChange() }
            readCatalogueDrift(statedTag: statedTag, systemName: systemName)
        case .refused(let fileName, let faults):
            chosenSystem = systemName
            diagnostics = faults
            diagnosticsFileName = fileName
            model = nil
            clearMessage()
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
        coalescer.schedule { [weak self] in self?.saveNow() }
    }

    /// Writes the drawn system back to the file it came from, and merges the
    /// answers on screen into its controls file.
    /// Writes from somewhere that cannot wait for it: the menu, or the timer
    /// that writes after an edit.
    func saveNow() {
        inFlight = Task { await save() }
    }

    func save() async {
        guard let root, let chosenSystem else { return }

        // Writing merges the answers on screen into the controls file, and
        // that merge re-imports the architecture, which lays the diagram out.
        // It is the most expensive thing an edit sets off, so it runs off the
        // main actor: dragging a node used to hold the window for as long as a
        // whole layout search took.
        isSaving = true
        defer { isSaving = false }

        let written = await Task.detached { [useCases] in
            useCases.saveSystem().execute(
                SaveSystemRequest(root: root, systemName: chosenSystem)
            )
        }.value

        switch written {
        case .saved:
            errorMessage = nil
            await saveAnswers(root: root, systemName: chosenSystem)
            savedRevision = model?.revision ?? 0
            fingerprint = currentFingerprint()
            hasFilesChangedOnDisk = false
        case .noSuchSystem:
            errorMessage = "This project no longer holds \"\(chosenSystem)\"."
        case .cannotWrite(let reason):
            errorMessage = "That system could not be written: \(reason)"
        }
    }

    private func saveAnswers(root: String, systemName: String) async {
        let merged = await Task.detached { [useCases] in
            useCases.saveSystemAnswers().execute(
                SaveSystemAnswersRequest(root: root, systemName: systemName)
            )
        }.value

        switch merged {
        case .saved(_, _, let unanswered, _):
            unansweredThreats = unanswered
            say(unanswered == 0
                ? "Saved."
                : "Saved. \(unanswered) threats have no answer.")
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

    /// True once this session has written a report, so the two controls and
    /// the File menu item have something to open. A report written by
    /// `threatmodeller compile` outside the application is not known to this
    /// session, and the item stays off until this session writes one.
    var canOpenReport: Bool { reportPath != nil }

    /// Opens the last report this session wrote, in the application the
    /// person uses for Markdown.
    func openLastReport() {
        guard let reportPath else { return }
        guard workspace.open(path: reportPath) else {
            errorMessage = "No application opened \(reportPath)."
            return
        }
        errorMessage = nil
    }

    /// Shows the last report this session wrote, in Finder.
    func revealLastReport() {
        guard let reportPath else { return }
        workspace.reveal(path: reportPath)
    }

    /// What the toolbar says, or nil when it says nothing.
    ///
    /// A load stage and a save message never show at once: a load states what
    /// is happening now, and a message states what happened.
    var toolbarMessage: String? {
        loading == nil ? lastActionMessage : nil
    }

    /// Says what a save or a report just did, and starts the wait that clears
    /// it. A new message replaces the one on screen and starts the wait again.
    private func say(_ message: String) {
        lastActionMessage = message
        messageTimer.schedule { [weak self] in
            self?.lastActionMessage = nil
        }
    }

    /// Takes the message off the screen now, and drops the wait.
    private func clearMessage() {
        messageTimer.cancel()
        lastActionMessage = nil
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
            say("Report: \(path)")
        case .noSuchSystem:
            errorMessage = "This project no longer holds \"\(chosenSystem)\"."
        case .cannotWrite(let reason):
            errorMessage = "The report could not be written: \(reason)"
        }
    }

    /// What the file states against what is in use, unless the person has
    /// already said to keep what the file states.
    ///
    /// A file that states no tag drifts from nothing: it has never named a
    /// catalogue, and naming one is the person's to do.
    private func readCatalogueDrift(statedTag: String?, systemName: String) {
        catalogueDrift = nil
        guard let statedTag else { return }
        let inUse = useCases.viewCatalogueVersion().execute(ViewCatalogueVersionRequest()).tag
        guard statedTag != inUse else { return }

        let drift = CatalogueDrift(
            systemName: systemName,
            fileName: "\(systemName).arch",
            stated: statedTag,
            inUse: inUse
        )
        guard defaults.bool(forKey: Self.driftKey(drift)) == false else { return }
        catalogueDrift = drift
    }

    /// Takes the catalogue in use: the model states the new tag, the save
    /// writes it into the file, and the system is read again against it.
    func takeTheCatalogueInUse() {
        guard let chosenSystem, let model else { return }
        _ = model.adoptCatalogueVersion()
        catalogueDrift = nil

        inFlight = Task { [weak self] in
            await self?.save()
            await self?.choose(chosenSystem)
        }
    }

    /// Keeps the tag the file states, and does not ask again for that file and
    /// that pair of tags. A dismissal belongs to the file, not to the window.
    func keepTheStatedCatalogue() {
        guard let drift = catalogueDrift else { return }
        defaults.set(true, forKey: Self.driftKey(drift))
        catalogueDrift = nil
    }

    /// The dismissal is remembered per file and per pair of tags, so a later
    /// catalogue asks again.
    private static func driftKey(_ drift: CatalogueDrift) -> String {
        "catalogue-drift:\(drift.fileName):\(drift.stated)->\(drift.inUse)"
    }

    func dismissDiagnostics() {
        diagnostics = []
    }
}
