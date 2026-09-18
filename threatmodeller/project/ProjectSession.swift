import DiagramRendering
import Foundation
import Observation
import SwiftUI
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
    /// Which columns the architecture stage shows. The standard sidebar
    /// button writes to the split view's own visibility, and a split view
    /// that holds none has nothing for the button to change, so the window
    /// holds it here and the button, the menu item and the key all write it.
    /// The choice outlives the run, the way the pointer mode does.
    var paletteColumns: NavigationSplitViewVisibility = .all {
        didSet { defaults.set(PaletteColumn.isShowing(paletteColumns), forKey: Self.paletteShowingKey) }
    }
    /// Which System sheet is on screen, or nil while none is. The System menu
    /// and the toolbar control both write it, and the project window presents
    /// the sheet it names.
    var systemSheet: SystemSheetKind?
    private let watcher: ProjectWatching
    private let defaults: UserDefaults
    private let coalescer: ChangeCoalescing
    /// Shows the palette, or hides it.
    func togglePalette() {
        paletteColumns = PaletteColumn.toggled(paletteColumns)
    }

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

    /// The rules the project states for itself, read over the drawn model by
    /// the same evaluation the report reads. Empty for a project with no
    /// policy file.
    private(set) var policyRules: [ReportPolicyRule] = []
    /// True after a person dismisses the breach notice. A change to the rules
    /// brings the notice back.
    private var isPolicyNoticeDismissed = false

    /// What `threatmodeller check` says about every system in the open
    /// project: the same categories, the same words. The toolbar states pass
    /// or fail from it and the check summary sheet lists it.
    private(set) var checkedSystems: [SystemCheck] = []

    /// What the systems picker states beside each name: the same unanswered
    /// count and worst level `threatmodeller list` prints for it. Keyed by
    /// system name.
    private(set) var systemSummaries: [String: SystemSummary] = [:]

    /// True when `threatmodeller check` would exit 0 for the open project.
    var passesCheck: Bool {
        checkedSystems.allSatisfy(\.passes)
    }

    /// How many findings fail the check. A warning prints but does not fail,
    /// so it does not count.
    var checkFailureCount: Int {
        checkedSystems.reduce(0) { $0 + $1.failureCount }
    }

    /// The session drawing the chosen system, or nil while nothing is drawn.
    private(set) var model: ThreatModelSession?

    /// What a load is doing, or nil when nothing is loading. The window says
    /// this, because opening a large model takes long enough that a still
    /// window reads as a broken one.
    private(set) var loading: LoadingStage?

    /// True while a write is in flight. The bar says so, because a write
    /// re-imports the architecture and that is not instant.
    private(set) var isSaving = false

    /// The diagram as the layout search last had it, while a load runs.
    private(set) var formingDiagram: LayOutModelResponse?

    /// What the reports are about: the names, the shapes, the zones and the
    /// flows. The use case that runs the search states it, because the search
    /// holds geometry and nothing else.
    private(set) var formingSubject: LayoutSubject?

    /// What samples the reports while a search runs, or nil when none runs.
    private var previewSampler: LayoutPreviewSampler?

    /// What the window draws in place of the canvas while the search runs, or
    /// nil when there is nothing to draw yet. A search that has reported
    /// nothing draws the stage on its own.
    var layoutPreview: (subject: LayoutSubject, layout: LayOutModelResponse)? {
        guard let formingSubject, let formingDiagram else { return nil }
        return (formingSubject, formingDiagram)
    }

    /// Starts drawing the layout search, and answers the sampler that draws
    /// it.
    ///
    /// The search reports from its own thread. The sampler stores each report
    /// and asks for a redraw at most once every
    /// `LayoutPreviewSampler.redrawInterval`, and the redraw reads the newest
    /// report here on the main actor.
    @discardableResult
    func watchTheLayout() -> LayoutPreviewSampler {
        formingDiagram = nil
        formingSubject = nil
        let sampler = LayoutPreviewSampler(redraw: { [weak self] in
            Task { @MainActor in self?.drawTheLayoutSoFar() }
        })
        previewSampler = sampler
        useCases.layoutProgress?.listen { [sampler] report in sampler.receive(report) }
        return sampler
    }

    /// Draws the last plan and stops listening. The preview stays on screen
    /// until the canvas takes over.
    func stopWatchingTheLayout() {
        previewSampler?.drawTheLast()
        useCases.layoutProgress?.listen(nil)
    }

    /// Drops the preview, because the canvas draws the model now.
    func forgetTheLayoutPreview() {
        previewSampler = nil
        formingDiagram = nil
        formingSubject = nil
    }

    /// One redraw. It reads the newest report rather than a report carried on
    /// the call, so a redraw that arrives late still draws the final plan.
    private func drawTheLayoutSoFar() {
        guard let previewSampler else { return }
        if let subject = useCases.layoutProgress?.subject { formingSubject = subject }
        formingDiagram = previewSampler.latest
    }

    /// What a load can be doing. The first four are the stages of opening a
    /// project, in the order they run. A synchronise is its own stage, not a
    /// step of opening.
    enum LoadingStage: String, CaseIterable {
        case readingTheProject
        case loadingLibraries
        case drawingTheSystem
        case scoringTheThreats
        case synchronisingAttack

        /// The stages of opening a project, for the "Step n of m" line.
        static let openingStages: [LoadingStage] = [
            .readingTheProject, .loadingLibraries, .drawingTheSystem, .scoringTheThreats
        ]

        /// What to say about this stage, to a person. `curl` reports no
        /// progress to this application, so the synchronise states its size
        /// instead of a percentage.
        var says: String {
            switch self {
            case .readingTheProject: "Reading the project\u{2026}"
            case .loadingLibraries: "Loading the libraries\u{2026}"
            case .drawingTheSystem: "Laying the diagram out\u{2026}"
            case .scoringTheThreats: "Scoring the threats\u{2026}"
            case .synchronisingAttack:
                "Synchronising ATT&CK, about \(AttackRelease.bundleBytes / 1_000_000) MB\u{2026}"
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
        pointerMode = PointerMode(rawValue: defaults.string(forKey: Self.pointerModeKey) ?? "")
            ?? PointerMode.standard
        pointerModeBox.mode = pointerMode
        if defaults.object(forKey: Self.paletteShowingKey) == nil {
            defaults.set(true, forKey: Self.paletteShowingKey)
        }
        paletteColumns = defaults.bool(forKey: Self.paletteShowingKey) ? .all : .doubleColumn
    }

    private static let autoSyncKey = "autoSync"
    private static let pointerModeKey = "pointerMode"
    private static let paletteShowingKey = "paletteShowing"

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

    /// Which pointing device the person drives both canvases with. It starts
    /// on Trackpad, and the toolbar and the View menu change it. The choice
    /// outlives the run.
    var pointerMode: PointerMode = .trackpad {
        didSet {
            defaults.set(pointerMode.rawValue, forKey: Self.pointerModeKey)
            pointerModeBox.mode = pointerMode
        }
    }

    /// The same mode as `pointerMode`, held by reference. `CanvasView` and
    /// `TreeCanvas` install their scroll monitor once and keep it running;
    /// the monitor reads this box at event time, so a change made after the
    /// canvas appeared still reaches the next wheel.
    let pointerModeBox = PointerModeBox()

    var hasErrors: Bool {
        diagnostics.contains { $0.severity == .error }
    }

    /// True when the drawn system breaks a policy rule.
    var hasPolicyBreach: Bool {
        policyRules.contains { $0.holds == false }
    }

    /// True while the window says a rule is breached. A person dismisses the
    /// notice; the sheet still lists the rules.
    var showsPolicyBreach: Bool {
        hasPolicyBreach && isPolicyNoticeDismissed == false
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
            // One history per open root. The sheet reads it, and the Report
            // stage draws the same rows.
            history = HistorySession(useCases: useCases, root: root)
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
            if let chosen {
                await choose(chosen)
            } else {
                checkedSystems = []
                staleAnswers = []
                systemSummaries = [:]
            }
        case .notAProject(let reason):
            self.root = nil
            systems = []
            model = nil
            staleAnswers = []
            watcher.stop()
            readPolicyRules()
            readCheckFindings()
            readSystemSummaries()
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
            // A check without the libraries would say the wrong things, so
            // the summary empties until the library parses.
            checkedSystems = []
            staleAnswers = []
            systemSummaries = [:]
            diagnostics = faults
            diagnosticsFileName = fileName
            errorMessage = "\(fileName) did not parse."
            return false
        case .notAProject(let reason):
            useCases.useLibraries([])
            model = nil
            staleAnswers = []
            errorMessage = "That is not a project: \(reason)"
            return false
        }
    }

    // MARK: answers the architecture no longer raises

    /// The answers in the controls file for threats the architecture stopped
    /// raising, as of the last read. Language guide 5.4: nothing deletes one,
    /// a person does, and `threatmodeller check` exits 1 while one remains.
    ///
    /// It is a stored property, not read fresh on every access. `@Observable`
    /// draws a view again only when a stored property the view read changes,
    /// so `readStaleAnswers` and `removeStaleAnswer` are the only two places
    /// that set it, and the panel draws again the moment either does.
    private(set) var staleAnswers: [StaleAnswer] = []

    /// Reads the controls file again for the answers it holds against
    /// threats the architecture no longer raises, and stores what it found.
    ///
    /// It reads the file rather than the model, because a stale answer never
    /// reaches the model.
    private func readStaleAnswers() {
        guard let root, let chosenSystem,
              case .listed(let answers) = useCases.listStaleAnswers().execute(
                  ListStaleAnswersRequest(root: root, systemName: chosenSystem)
              ) else {
            staleAnswers = []
            return
        }
        staleAnswers = answers
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
        readStaleAnswers()
        readCheckFindings()
        readSystemSummaries()
    }

    /// Deletes every stale answer this system holds, in one read and one
    /// write of the controls file, because a person confirmed the sheet
    /// that lists what each one holds.
    func removeStaleAnswers() async {
        guard let root, let chosenSystem else { return }

        useCases.removeStaleAnswers()
            .execute(RemoveStaleAnswersRequest(root: root, systemName: chosenSystem))
            .describe(into: &errorMessage)

        fingerprint = currentFingerprint()
        readStaleAnswers()
        readCheckFindings()
    }

    // MARK: the attack trees this system states

    /// The trees the system's `.attacktree` file states, for the editor. It
    /// reads the file rather than the model, because the editor writes the
    /// file.
    var attackTreeSources: [SourceAttackTree] {
        guard let root, let chosenSystem else { return [] }
        guard case .listed(let trees, _, _) = useCases.listAttackTreeSources().execute(
            ListAttackTreeSourcesRequest(root: root, systemName: chosenSystem)
        ) else { return [] }
        return trees
    }

    /// What the system's `.attacktree` file states about the catalogue
    /// against the catalogue in use, or nil while the two agree or the file
    /// states no tag. A file that states no tag has never named one, and
    /// naming one is the person's to do, the way the `.arch` file's own
    /// notice states it.
    var attackTreeCatalogueDrift: CatalogueDrift? {
        guard let root, let chosenSystem else { return nil }
        guard case .listed(_, _, let statedTag?) = useCases.listAttackTreeSources().execute(
            ListAttackTreeSourcesRequest(root: root, systemName: chosenSystem)
        ) else { return nil }
        let inUse = useCases.viewCatalogueVersion().execute(ViewCatalogueVersionRequest()).tag
        guard statedTag != inUse else { return nil }
        return CatalogueDrift(
            systemName: chosenSystem,
            fileName: "\(chosenSystem).attacktree",
            stated: statedTag,
            inUse: inUse
        )
    }

    /// Takes the catalogue in use into the `.attacktree` file, the way
    /// `takeTheCatalogueInUse()` takes it into the `.arch` file.
    func takeAttackTreeCatalogueInUse() {
        let tag = useCases.viewCatalogueVersion().execute(ViewCatalogueVersionRequest()).tag
        inFlight = Task { [weak self] in await self?.writeAttackTreeCatalogue(tag) }
    }

    /// Writes the catalogue tag into the `.attacktree` file and reads the
    /// project again, so the notice clears once the file agrees.
    private func writeAttackTreeCatalogue(_ tag: String) async {
        guard let root, let chosenSystem else { return }

        useCases.takeAttackTreeCatalogue()
            .execute(
                TakeAttackTreeCatalogueRequest(
                    root: root,
                    systemName: chosenSystem,
                    systemDisplayName: model?.canvas.name,
                    tag: tag
                )
            )
            .describe(into: &errorMessage)

        await reloadFromDisk()
    }

    /// Writes one tree and reads the project again, so the score beside the
    /// tree is the score the model now gives it.
    func writeAttackTree(_ tree: SourceAttackTree) async {
        guard let root, let chosenSystem else { return }

        useCases.writeAttackTree()
            .execute(
                WriteAttackTreeRequest(
                    root: root,
                    systemName: chosenSystem,
                    systemDisplayName: model?.canvas.name,
                    tree: tree
                )
            )
            .describe(into: &errorMessage)

        await reloadFromDisk()
    }

    /// Deletes one tree and reads the project again.
    func removeAttackTree(_ treeId: String) async {
        guard let root, let chosenSystem else { return }

        useCases.removeAttackTree()
            .execute(
                RemoveAttackTreeRequest(root: root, systemName: chosenSystem, treeId: treeId)
            )
            .describe(into: &errorMessage)

        await reloadFromDisk()
    }

    // MARK: the governance this system states

    /// The stanzas the system's `.governance` file states, for the editors.
    /// They read the file rather than the model, because the editors write
    /// the file.
    var governanceSource: GovernanceSource? {
        guard let root, let chosenSystem else { return nil }
        guard case .listed(let source, _) = useCases.listGovernance().execute(
            ListGovernanceRequest(root: root, systemName: chosenSystem)
        ) else { return nil }
        return source
    }

    /// The work and action stanzas the file states, for the planned-work
    /// list. A stale stanza is a person's to delete in the file, so the list
    /// leaves it out.
    var plannedWork: [PlannedWorkItem] {
        guard let source = governanceSource else { return [] }

        var items: [PlannedWorkItem] = []
        for threat in source.threats where threat.isStale == false {
            for work in threat.work where work.isStale == false {
                items.append(
                    PlannedWorkItem(
                        place: .threat(
                            threatId: threat.threatId,
                            sourceKind: threat.sourceKind,
                            sourceId: threat.sourceId
                        ),
                        work: work,
                        placeSays: "\(threat.threatId) on \(threat.sourceKind) \"\(threat.sourceId)\""
                    )
                )
            }
        }
        for action in source.actions where action.isStale == false {
            items.append(
                PlannedWorkItem(
                    place: .action,
                    work: action,
                    placeSays: "an action the architecture declares"
                )
            )
        }
        return items
    }

    /// Writes who carries one accepted risk and reads the project again, so
    /// the card and the check summary state the entry.
    func writeRiskAcceptance(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        accepted: SourceAcceptedRisk
    ) async {
        guard let root, let chosenSystem else { return }

        useCases.writeRiskAcceptance()
            .execute(
                WriteRiskAcceptanceRequest(
                    root: root,
                    systemName: chosenSystem,
                    systemDisplayName: model?.canvas.name,
                    threatId: threatId,
                    sourceKind: sourceKind,
                    sourceId: sourceId,
                    accepted: accepted
                )
            )
            .describe(into: &errorMessage)

        await reloadFromDisk()
    }

    /// Writes one piece of planned work and reads the project again.
    func writePlannedWork(place: PlannedWorkPlace, work: SourcePlannedWork) async {
        guard let root, let chosenSystem else { return }

        useCases.writePlannedWork()
            .execute(
                WritePlannedWorkRequest(
                    root: root,
                    systemName: chosenSystem,
                    systemDisplayName: model?.canvas.name,
                    place: place,
                    work: work
                )
            )
            .describe(into: &errorMessage)

        await reloadFromDisk()
    }

    /// Writes one severity decision into the controls file and reads the
    /// project again, so the threat re-scores with it.
    func writeSeverityDecision(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        decision: SeverityDecision
    ) async {
        guard let root, let chosenSystem else { return }

        let response = useCases.writeSeverityDecision()
            .execute(
                WriteSeverityDecisionRequest(
                    root: root,
                    systemName: chosenSystem,
                    systemDisplayName: model?.canvas.name,
                    threatId: threatId,
                    sourceKind: sourceKind,
                    sourceId: sourceId,
                    decision: decision
                )
            )
        response.describe(into: &errorMessage)

        // A refused write changed no file, and reading the project again
        // clears the message that says why.
        guard case .written = response else { return }
        await reloadFromDisk()
    }

    /// Removes one severity decision and reads the project again, so the
    /// catalogue's severity stands.
    func removeSeverityDecision(
        threatId: String,
        sourceKind: String,
        sourceId: String
    ) async {
        guard let root, let chosenSystem else { return }

        let response = useCases.removeSeverityDecision()
            .execute(
                RemoveSeverityDecisionRequest(
                    root: root,
                    systemName: chosenSystem,
                    threatId: threatId,
                    sourceKind: sourceKind,
                    sourceId: sourceId
                )
            )
        response.describe(into: &errorMessage)

        guard case .removed = response else { return }
        await reloadFromDisk()
    }

    /// Writes a decision from somewhere that cannot wait for it.
    func saveSeverityDecision(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        decision: SeverityDecision
    ) {
        inFlight = Task {
            await writeSeverityDecision(
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId,
                decision: decision
            )
        }
    }

    // MARK: how often a threat happens

    /// Writes one likelihood finding into the controls file and reads the
    /// project again, so the threat re-scores with it.
    func writeLikelihoodFinding(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        label: String,
        tier: String?,
        prior: Int?,
        rationale: String,
        sources: [String]
    ) async {
        guard let root, let chosenSystem else { return }

        let response = useCases.writeLikelihoodFinding()
            .execute(
                WriteLikelihoodFindingRequest(
                    root: root,
                    systemName: chosenSystem,
                    systemDisplayName: model?.canvas.name,
                    threatId: threatId,
                    sourceKind: sourceKind,
                    sourceId: sourceId,
                    label: label,
                    tier: tier,
                    prior: prior,
                    rationale: rationale,
                    sources: sources
                )
            )
        response.describe(into: &errorMessage)

        // A refused write changed no file, and reading the project again
        // clears the message that says why.
        guard case .written = response else { return }
        await reloadFromDisk()
    }

    /// Writes a finding from somewhere that cannot wait for it.
    func saveLikelihoodFinding(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        label: String,
        tier: String?,
        prior: Int?,
        rationale: String,
        sources: [String]
    ) {
        inFlight = Task {
            await writeLikelihoodFinding(
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId,
                label: label,
                tier: tier,
                prior: prior,
                rationale: rationale,
                sources: sources
            )
        }
    }

    /// Deletes a decision from somewhere that cannot wait for it.
    func deleteSeverityDecision(threatId: String, sourceKind: String, sourceId: String) {
        inFlight = Task {
            await removeSeverityDecision(
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId
            )
        }
    }

    // MARK: what a threat harms

    /// Writes one threat's whole `impacts` list into the controls file and
    /// reads the project again, so the filter reads what the chips now show.
    func writeImpacts(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        impacts: [String]
    ) async {
        guard let root, let chosenSystem else { return }

        let response = useCases.writeImpacts()
            .execute(
                WriteImpactsRequest(
                    root: root,
                    systemName: chosenSystem,
                    systemDisplayName: model?.canvas.name,
                    threatId: threatId,
                    sourceKind: sourceKind,
                    sourceId: sourceId,
                    impacts: impacts
                )
            )
        response.describe(into: &errorMessage)

        // A refused write changed no file, and reading the project again
        // clears the message that says why.
        guard case .written = response else { return }
        await reloadFromDisk()
    }

    /// Writes an impacts list from somewhere that cannot wait for it, such
    /// as a chip's tap.
    func saveImpacts(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        impacts: [String]
    ) {
        inFlight = Task {
            await writeImpacts(
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId,
                impacts: impacts
            )
        }
    }

    // MARK: what to do about a threat

    /// Writes one `recommendation` block into the controls file and reads the
    /// project again, so the card shows what the file now holds.
    ///
    /// `replacing` names the block an edit changes, by its text. Nil writes a
    /// new block.
    func writeRecommendation(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        replacing: String? = nil,
        text: String,
        note: String? = nil,
        sources: [String] = []
    ) async {
        guard let root, let chosenSystem else { return }

        let response = useCases.writeRecommendation()
            .execute(
                WriteRecommendationRequest(
                    root: root,
                    systemName: chosenSystem,
                    systemDisplayName: model?.canvas.name,
                    threatId: threatId,
                    sourceKind: sourceKind,
                    sourceId: sourceId,
                    replacing: replacing,
                    text: text,
                    note: note,
                    sources: sources
                )
            )
        response.describe(into: &errorMessage)

        // A refused write changed no file, and reading the project again
        // clears the message that says why.
        guard case .written = response else { return }
        await reloadFromDisk()
    }

    /// Takes one `recommendation` block out of the controls file and reads the
    /// project again.
    func removeRecommendation(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        text: String
    ) async {
        guard let root, let chosenSystem else { return }

        let response = useCases.removeRecommendation()
            .execute(
                RemoveRecommendationRequest(
                    root: root,
                    systemName: chosenSystem,
                    threatId: threatId,
                    sourceKind: sourceKind,
                    sourceId: sourceId,
                    text: text
                )
            )
        response.describe(into: &errorMessage)

        guard case .removed = response else { return }
        await reloadFromDisk()
    }

    /// Writes a recommendation from somewhere that cannot wait for it, such
    /// as the editor's Save button.
    func saveRecommendation(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        replacing: String? = nil,
        text: String,
        note: String? = nil,
        sources: [String] = []
    ) {
        inFlight = Task {
            await writeRecommendation(
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId,
                replacing: replacing,
                text: text,
                note: note,
                sources: sources
            )
        }
    }

    /// Removes a recommendation from somewhere that cannot wait for it.
    func deleteRecommendation(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        text: String
    ) {
        inFlight = Task {
            await removeRecommendation(
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId,
                text: text
            )
        }
    }

    /// Writes an acceptance from somewhere that cannot wait for it.
    func saveRiskAcceptance(
        threatId: String,
        sourceKind: String,
        sourceId: String,
        accepted: SourceAcceptedRisk
    ) {
        inFlight = Task {
            await writeRiskAcceptance(
                threatId: threatId,
                sourceKind: sourceKind,
                sourceId: sourceId,
                accepted: accepted
            )
        }
    }

    /// Writes planned work from somewhere that cannot wait for it.
    func savePlannedWork(place: PlannedWorkPlace, work: SourcePlannedWork) {
        inFlight = Task { await writePlannedWork(place: place, work: work) }
    }

    /// Writes a tree from somewhere that cannot wait for it.
    func saveAttackTree(_ tree: SourceAttackTree) {
        inFlight = Task { await writeAttackTree(tree) }
    }

    /// Deletes a tree from somewhere that cannot wait for it.
    func deleteAttackTree(_ treeId: String) {
        inFlight = Task { await removeAttackTree(treeId) }
    }

    /// Deletes one from somewhere that cannot wait for it.
    func deleteStaleAnswer(_ answer: StaleAnswer) {
        inFlight = Task { await removeStaleAnswer(answer) }
    }

    /// Deletes every stale answer from somewhere that cannot wait for it.
    func deleteStaleAnswers() {
        inFlight = Task { await removeStaleAnswers() }
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

    /// Reads the files again, the way `reload()` does, and drops the
    /// selection down to what the reloaded model still holds.
    ///
    /// The toolbar and the File menu call this, so a person can ask for a
    /// reload without waiting for the files-changed notice, and without the
    /// canvas keeping a selection that points at an element that is gone. The
    /// notice keeps its own plain `reload()`.
    func reload(keepingSelectionIn canvas: CanvasState) {
        inFlight = Task {
            await reloadFromDisk()
            canvas.retainOnly(
                componentIds: Set(model?.canvas.components.map(\.id) ?? []),
                connectionIds: Set(model?.canvas.connections.map(\.id) ?? []),
                zoneIds: Set(model?.canvas.zones.map(\.id) ?? [])
            )
        }
    }

    /// Writes an example, or a system with a name and nothing else, from
    /// somewhere that cannot wait for it.
    func startWriting(_ from: ProjectStart) {
        inFlight = Task { await start(from) }
    }

    /// The load in flight, so a caller that has to know when it finished can
    /// wait for it. A test is the only caller that does.
    private var inFlight: Task<Void, Never>?

    /// Waits for the load in flight, if there is one, and for the file work
    /// the window queued.
    func settle() async {
        await inFlight?.value
        await fileWork?.value
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
        defer {
            loading = nil
            forgetTheLayoutPreview()
        }

        // Reading a system parses its file and lays the diagram out, and the
        // layout is most of what opening a model costs. It runs off the main
        // actor so the window keeps answering while it does. The store guards
        // itself with a lock, which is what lets this leave.
        loading = .drawingTheSystem
        // The search reports every plan that beats the best so far, from
        // whatever thread it runs on. The sampler stores each report and the
        // window redraws on its own interval.
        watchTheLayout()
        let outcome = await Task.detached { [useCases] in
            useCases.openSystem().execute(
                OpenSystemRequest(root: root, systemName: systemName)
            )
        }.value
        stopWatchingTheLayout()

        switch outcome {
        case .opened(_, let warnings, let statedTag):
            chosenSystem = systemName
            diagnostics = warnings
            diagnosticsFileName = "\(systemName).arch"
            errorMessage = nil
            clearMessage()
            loading = .scoringTheThreats
            let drawn = ThreatModelSession(useCases: useCases, projectRoot: root, projectSystem: systemName)
            // The history belongs to the project, so a model read again keeps
            // what the person sampled.
            drawn.sampledHistory = sampledHistory
            model = drawn
            savedRevision = drawn.revision
            hasFilesChangedOnDisk = false
            // A MITRE id field with no matrix on this machine offers the
            // synchronise action, and the one synchronise path is here.
            drawn.onSynchroniseAttack = { [weak self] in await self?.synchroniseAttack() }
            // A merge's Undo and Redo write bytes into the same files the
            // save writes, so both join the one file work queue.
            drawn.onFileWork = { [weak self] work in
                self?.queueFileWork { work() }
            }
            // Set last, so building the session does not count as a change.
            drawn.onChange = { [weak self] in self?.modelDidChange() }
            readPolicyRules()
            readCheckFindings()
            readStaleAnswers()
            readSystemSummaries()
            readCatalogueDrift(statedTag: statedTag, systemName: systemName)
        case .refused(let fileName, let faults):
            chosenSystem = systemName
            diagnostics = faults
            diagnosticsFileName = fileName
            model = nil
            clearMessage()
            savedRevision = 0
            hasFilesChangedOnDisk = false
            readPolicyRules()
            readCheckFindings()
            readStaleAnswers()
            readSystemSummaries()
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
        // A technology change drops the answers on threats the new technology
        // does not raise. The person is told which, once.
        let dropped = model?.takeDroppedAnswerThreatIds() ?? []
        if dropped.isEmpty == false {
            diagnostics = dropped.map {
                Diagnostic(
                    severity: .warning,
                    line: 0,
                    column: 0,
                    message: "the answer on \($0) went with the technology that raised it"
                )
            }
            diagnosticsFileName = chosenSystem.map { "\($0).arch" }
        }
        // A merge drops an answer the kept component already holds, or one
        // on a threat the kept technology does not raise. The person is told
        // which, once.
        let droppedByMerge = model?.takeDroppedMergeAnswers() ?? []
        if droppedByMerge.isEmpty == false {
            diagnostics = droppedByMerge.map {
                Diagnostic(
                    severity: .warning,
                    line: 0,
                    column: 0,
                    message: "the answer on \($0) was dropped by the merge"
                )
            }
            diagnosticsFileName = chosenSystem.map { "\($0).controls" }
        }

        guard isAutoSyncOn, hasUnsavedChanges else { return }
        coalescer.schedule { [weak self] in self?.saveNow() }
    }

    /// What a synchronise will do and what the data is for, for the question
    /// the window asks first.
    var attackSynchroniseQuestion: String {
        let tag = attackTag
        return "Download MITRE ATT&CK \(tag) from \(AttackRelease.address(of: tag))? "
            + "It gives each technique in the report its name, and it lists the MITRE "
            + "groups a project can face as threat actors. "
            + "That is about \(AttackRelease.bundleBytes / 1_000_000) MB, and it is written to "
            + "this machine, not to the project."
    }

    /// The tag a synchronise would take: the one the project states, else the
    /// one this application offers.
    var attackTag: String {
        guard let root else { return AttackRelease.default }
        return useCases.attackTag(root: root)
    }

    /// Brings the ATT&CK matrix onto this machine. It runs off the main actor,
    /// because it downloads about 53 MB.
    func synchroniseAttack(tag: String? = nil) async {
        guard let root else { return }
        errorMessage = nil
        loading = .synchronisingAttack
        defer { loading = nil }

        let useCases = self.useCases
        let response = await Task.detached {
            useCases.synchroniseAttack().execute(
                SynchroniseAttackRequest(root: root, tag: tag)
            )
        }.value

        switch response {
        case .synchronised(let tag, let groups, let techniques):
            say("ATT&CK \(tag): \(groups) groups, \(techniques) techniques")
            useCases.forgetAttackData()
            reload()
        case .notAProject(let reason), .cannotDownload(let reason),
             .cannotExtract(let reason), .cannotWrite(let reason):
            // An error stays until a person dismisses it. `say` clears itself,
            // and a person who looked away must still find the failure.
            errorMessage = "ATT&CK was not synchronised: \(reason). "
                + "The data on this machine is unchanged. "
                + "Fix the cause and press Synchronise ATT&CK to try again."
        }
    }

    /// The ATT&CK data this machine holds: the tag, the counts, and when it
    /// was written. The About window states it at any time.
    var attackHolding: ViewAttackDataResponse {
        useCases.viewAttackData().execute(ViewAttackDataRequest())
    }

    /// Whether the held data is the data the project's lock file states: the
    /// answer `threatmodeller attack verify` gives, readable in the window.
    var attackAgreement: VerifyAttackResponse? {
        guard let root else { return nil }
        return useCases.verifyAttack().execute(VerifyAttackRequest(root: root))
    }

    /// The libraries this project reads, each with its repository and its tag.
    /// The About window states them under the catalogue line.
    var libraries: [ListedLibrary] {
        guard let root else { return [] }
        guard case .listed(let libraries) = useCases.listLibraries()
            .execute(ListLibrariesRequest(root: root)) else { return [] }
        return libraries
    }

    /// Moves a technology the drawn system defines into a library file this
    /// project holds, so every system in the project reads it and another
    /// project vendors it with `threatmodeller library add`.
    ///
    /// It answers the technology's new identifier, or nil when nothing moved.
    @discardableResult
    func moveTechnologyToLibrary(_ technologyId: String, into libraryLabel: String) -> String? {
        guard let root else { return nil }

        switch useCases.moveTechnologyToLibrary().execute(
            MoveTechnologyToLibraryRequest(
                root: root,
                technologyId: technologyId,
                libraryLabel: libraryLabel
            )
        ) {
        case .moved(let newId, let path):
            errorMessage = nil
            say("Moved to \(path)")
            reload()
            return newId
        case .unknownTechnology:
            errorMessage = "This model no longer defines that technology."
        case .alreadyInTheLibrary(let held):
            errorMessage = "The library already states \(held)."
        case .notAProject(let reason):
            errorMessage = "That is not a project: \(reason)"
        case .cannotWrite(let reason):
            errorMessage = "The library could not be written: \(reason)"
        }
        return nil
    }

    /// Lays the drawn diagram out again, and moves the elements to the result.
    ///
    /// The layout search is the most expensive thing this application runs, so
    /// it runs off the main actor and the window says what it is doing while
    /// it runs. With elements named, only those move.
    func layOutDiagram(componentIds: [String] = [], zoneIds: [String] = []) async {
        guard let model else { return }
        loading = .drawingTheSystem
        // Lay Out on an open system draws the same preview as opening one.
        watchTheLayout()
        defer {
            loading = nil
            forgetTheLayoutPreview()
        }

        let useCases = self.useCases
        await Task.detached {
            _ = useCases.arrangeDiagram().execute(
                ArrangeDiagramRequest(componentIds: componentIds, zoneIds: zoneIds)
            )
        }.value
        stopWatchingTheLayout()

        model.reread()
    }

    // MARK: the file work queue

    /// The file work the window asked for, the piece asked for last.
    ///
    /// Auto Sync's save, a save from the menu and a merge's file restore all
    /// join this queue, and the queue runs one piece at a time in the order
    /// the window asked for. Two pieces at once let a save read a file a
    /// restore was still writing, and the bytes that stayed were the bytes of
    /// whichever piece finished last.
    private var fileWork: Task<Void, Never>?

    /// The most pieces of file work that ran at the same time. The rule is
    /// one. A test reads this to hold the rule.
    private(set) var mostFileWorkAtOnce = 0
    private var fileWorkRunning = 0

    /// Puts one piece of file work at the end of the queue and answers the
    /// task that runs it, so a caller can wait for the bytes to land.
    @discardableResult
    private func queueFileWork(_ work: @escaping @MainActor () async -> Void) -> Task<Void, Never> {
        let earlier = fileWork
        let queued = Task { @MainActor [weak self] in
            await earlier?.value
            guard let self else { return }
            self.fileWorkRunning += 1
            self.mostFileWorkAtOnce = max(self.mostFileWorkAtOnce, self.fileWorkRunning)
            await work()
            self.fileWorkRunning -= 1
        }
        fileWork = queued
        return queued
    }

    /// Writes the drawn system back to the file it came from, and merges the
    /// answers on screen into its controls file.
    /// Writes from somewhere that cannot wait for it: the menu, or the timer
    /// that writes after an edit.
    func saveNow() {
        inFlight = queueFileWork { [weak self] in await self?.writeTheFiles() }
    }

    /// Writes the files and answers, and returns when the bytes have landed.
    /// It waits for every piece of file work the window asked for before it,
    /// so a caller that returns from here reads the bytes the window meant.
    func save() async {
        await queueFileWork { [weak self] in await self?.writeTheFiles() }.value
    }

    private func writeTheFiles() async {
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
            readPolicyRules()
            readCheckFindings()
            readStaleAnswers()
            readSystemSummaries()
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

    // MARK: importing from Terraform

    /// What the last Terraform import did, in the words `threatmodeller
    /// import terraform` prints for it. The result sheet reads this.
    private(set) var terraformImportResult: TerraformImportResult?

    /// Imports the JSON `terraform show -json` wrote into the open system's
    /// architecture, and reads the project again so the window shows the
    /// imported components without a separate reload.
    ///
    /// A file that does not parse as that JSON, or an existing `.arch` file
    /// that does not parse, writes nothing and only sets `errorMessage`: the
    /// result sheet is for a report on what an import drew, not for a
    /// fault.
    func importTerraform(fileAt path: String) async {
        guard let root, let chosenSystem else { return }
        guard let stateText = try? String(contentsOfFile: path, encoding: .utf8) else {
            errorMessage = "\((path as NSString).lastPathComponent) could not be read."
            return
        }

        switch useCases.importTerraformIntoSystem().execute(
            ImportTerraformIntoSystemRequest(
                root: root,
                systemName: chosenSystem,
                stateText: stateText
            )
        ) {
        case .imported(let writtenPath, let response):
            guard case .imported = response else {
                errorMessage = response.importLines(path: writtenPath).joined(separator: "\n")
                return
            }
            errorMessage = nil
            terraformImportResult = TerraformImportResult(
                path: writtenPath,
                lines: response.importLines(path: writtenPath)
            )
            await reloadFromDisk()
        case .noSuchSystem:
            errorMessage = "This project no longer holds \"\(chosenSystem)\"."
        case .notAProject(let reason):
            errorMessage = "That is not a project: \(reason)"
        case .cannotWrite(let reason):
            errorMessage = "The system could not be written: \(reason)"
        }
    }

    /// Takes the result sheet off the screen.
    func dismissTerraformImportResult() {
        terraformImportResult = nil
    }

    // MARK: splitting a flat system into a directory

    /// True when the open system's files already sit in the directory form,
    /// so *Split into Directory* has nothing to do. False while nothing is
    /// known about the system yet.
    var chosenSystemIsSplit: Bool {
        guard let chosenSystem else { return false }
        return systemSummaries[chosenSystem]?.isSplit ?? false
    }

    /// Moves the open system's files into the directory form:
    /// `threatmodel/<name>/arch/`, `controls/` and `attacktree/`, and reads
    /// the project again so the window shows the same system read from the
    /// directory.
    func splitSystem() async {
        guard let root, let chosenSystem else { return }

        switch useCases.splitSystem().execute(
            SplitSystemRequest(root: root, systemName: chosenSystem)
        ) {
        case .split:
            errorMessage = nil
            await reloadFromDisk()
        case .noSuchSystem:
            errorMessage = "This project no longer holds \"\(chosenSystem)\"."
        case .alreadySplit:
            errorMessage = "\"\(chosenSystem)\" is already a directory."
        case .cannotWrite(let reason):
            errorMessage = "The system could not be split: \(reason)"
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

    /// Which file `Generate Report` writes on the Report stage.
    enum ReportFormat: String, CaseIterable, Identifiable {
        case markdown
        case html
        case pdf

        var id: String { rawValue }

        var label: String {
            switch self {
            case .markdown: "Markdown"
            case .html: "HTML"
            case .pdf: "PDF"
            }
        }

        /// The export the File menu runs for the same format.
        var exportKind: ReportExporter.Kind {
            switch self {
            case .markdown: .markdown
            case .html: .html
            case .pdf: .pdf
            }
        }
    }

    /// The format the Report stage writes. Markdown, until a person picks
    /// another.
    var reportFormat: ReportFormat = .markdown

    /// The project's git history, read when a person asks. Nil until a
    /// project is open.
    private(set) var history: HistorySession?

    /// What the last sampling found, which is nothing until a person samples.
    var sampledHistory: RiskHistory { history?.found ?? RiskHistory() }

    /// Samples the history, which is the read the History sheet runs. The
    /// Report stage offers it where the Risk over time section would be.
    func sampleTheHistory() async {
        await history?.read()
        model?.sampledHistory = sampledHistory
    }

    /// Writes the report the format picker names.
    ///
    /// Markdown goes to the system's report path in the project, with no save
    /// panel: it is the file `threatmodeller compile` writes and the bytes the
    /// File menu's Markdown export writes. HTML and PDF go where the person
    /// says, because the project holds no place for them.
    func generateReport(chooseFile: ReportExporter.ChooseFile? = nil) async {
        guard reportFormat != .markdown else { return compileReport() }
        guard let model else { return }

        var exporter = ReportExporter(session: model)
        if let chooseFile { exporter.chooseFile = chooseFile }
        guard let written = await exporter.exportNamingTheFile(reportFormat.exportKind) else {
            return
        }
        errorMessage = nil
        reportPath = written.path
        say("Report: \(written.path)")
    }

    /// Writes the Markdown report for the drawn system.
    ///
    /// The pictures and the history go with it, the way the executable's
    /// report verb passes them, so the file and the stage hold the same
    /// figures.
    func compileReport() {
        guard let root, let chosenSystem, let model else { return }

        let sampled = sampledHistory
        let drawn = model.reportPictureSet(history: sampled.rows)

        switch useCases.compileSystemReport().execute(
            CompileSystemReportRequest(
                root: root,
                systemName: chosenSystem,
                threatPictures: drawn.threatPictures,
                controlPictures: drawn.controlPictures,
                pictureFiles: drawn.sources,
                riskOverTimePicture: drawn.riskOverTimePicture,
                history: sampled.rows,
                historyTruncated: sampled.truncated
            )
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

    /// Takes the notice off the screen: the diagnostics, the error, and the
    /// breach with them. An error never clears itself, so this is how one
    /// goes.
    func dismissDiagnostics() {
        diagnostics = []
        errorMessage = nil
        isPolicyNoticeDismissed = true
    }

    /// Reads every system's files again and keeps what `list` would print
    /// about each, so the picker states the same numbers as the verb.
    private func readSystemSummaries() {
        guard let root else {
            systemSummaries = [:]
            return
        }
        var found: [String: SystemSummary] = [:]
        for name in systems {
            guard case .listed(let summary) = useCases.listSystem().execute(
                ListSystemRequest(root: root, systemName: name)
            ) else { continue }
            found[name] = summary
        }
        systemSummaries = found
    }

    /// Reads every system's files again and keeps what `check` would print
    /// about each, so the window states the answer the verb gives.
    private func readCheckFindings() {
        guard let root else {
            checkedSystems = []
            return
        }
        checkedSystems = systems.compactMap { name in
            guard case .checked(let found) = useCases.checkSystem().execute(
                CheckSystemRequest(root: root, systemName: name)
            ) else { return nil }
            return found
        }
    }

    /// Reads the rules again, over the drawn model. Rules that changed bring
    /// a dismissed breach notice back.
    private func readPolicyRules() {
        let read: [ReportPolicyRule] = model == nil
            ? []
            : useCases.buildThreatModelReport()
                .execute(BuildThreatModelReportRequest()).report.policy
        if read != policyRules { isPolicyNoticeDismissed = false }
        policyRules = read
    }
}

/// One piece of planned work the governance file states, and where it sits.
struct PlannedWorkItem: Identifiable, Equatable {
    let place: PlannedWorkPlace
    let work: SourcePlannedWork
    /// Where the work sits, said for a list row.
    let placeSays: String

    /// The stanza's identity: where it sits and the label that keys it.
    var id: String {
        switch place {
        case .threat(let threatId, let sourceKind, let sourceId):
            "\(threatId)@\(sourceKind):\(sourceId)#\(work.label)"
        case .action:
            "action#\(work.label)"
        }
    }
}

/// What a Terraform import wrote, for the result sheet: where it wrote, and
/// what it says about what it mapped and what it could not, in the words
/// `threatmodeller import terraform` prints for it.
struct TerraformImportResult: Equatable {
    let path: String
    let lines: [String]
}
