import AppKit
import DiagramRendering
import Observation
import ThreatModelKit

/// Translates user intent into use case calls and publishes the responses.
/// Holds no business rules and names no gateway.
///
/// Main-actor isolated: every caller is a SwiftUI view, and the use cases it
/// calls are synchronous. `ThreatModelGateway` has no atomic append, so a
/// second concurrent caller would lose a change; the isolation keeps that
/// impossible while the port stays as it is.
@MainActor
@Observable
final class ThreatModelSession {
    private let useCases: UseCaseFactory
    /// Where a copy goes and where a paste comes from.
    private let clipboard: Clipboard

    private(set) var palette: [ListedProvider] = []
    /// What the canvas draws. Spec section 9 calls this the canvas snapshot.
    private(set) var canvas = ViewThreatModelResponse(
        name: "Untitled",
        components: [],
        connections: [],
        zones: []
    )
    /// The threats, in the order the list draws them.
    ///
    /// The order holds still while a person answers the register one card at a
    /// time. `AssessThreatModel` answers worst first; this list keeps the
    /// order it was last sorted into, so a card the person is working in does
    /// not move out from under the pointer when its score changes.
    private(set) var threats: [AssessedThreat] = []
    /// The trees the model bound and scored. The attack tree editor states
    /// each tree's score beside it, so a person writing one sees what it is
    /// worth.
    var attackTrees: [BoundAttackTree] {
        useCases.assessThreatModel().execute(AssessThreatModelRequest()).attackTrees
    }
    /// How many rows sit somewhere other than where a sort would put them.
    /// Zero while the list is in order, which is when the Reorder button is
    /// not shown.
    private(set) var rowsOutOfOrder = 0
    /// The row keys of the drawn list, so the next read keeps this order.
    private var drawnOrder: [String] = []
    /// True when the next read sorts rather than holds. It starts true, so a
    /// model that has just loaded is worst first.
    private var resortsOnNextRead = true
    /// The risk of every element on the diagram, by source id. The canvas
    /// paints from this, so the picture and the threat list never disagree.
    private(set) var elementRisks: [String: ElementRisk] = [:]
    /// What guards every element on the diagram, by source id. The canvas
    /// names these beside the boundary a flow crosses.
    private(set) var elementGuards: [String: [EdgeGuard]] = [:]
    private(set) var summary = SummariseRiskResponse(
        totalThreats: 0,
        byLevel: [],
        byStride: [],
        controlsOffered: 0,
        controlsRecorded: 0
    )
    /// The severities the override menu offers.
    private(set) var severityChoices: [AssessedSeverity] = []
    private(set) var pathwayMitigations = ListPathwayMitigationsResponse(
        isMasterEnabled: false,
        mitigations: []
    )
    private(set) var errorMessage: String?
    /// The threats the technology editor offers. Read once: the catalogue does
    /// not change while the application runs.
    private(set) var threatChoices: [ThreatChoice] = []
    /// How many times this session has read the model back. It starts at 1,
    /// and every change raises it. `ProjectSession` compares it with the
    /// number it recorded to answer whether anything on screen is unsaved.
    private(set) var revision = 0
    /// The groups the threat list draws closed, by source id.
    ///
    /// It lives on the session rather than on the view, so it survives a stage
    /// change and belongs to one system: opening another system builds another
    /// session, which starts with every group open.
    private(set) var collapsedGroups: Set<String> = []
    /// What a window that owns this session wants to know after every change.
    /// A document window sets nothing. A project window writes the files.
    var onChange: (() -> Void)?

    /// The open project's root, so a report export reads the project's
    /// template. Nil when no project holds this model.
    private let projectRoot: String?
    /// The open system's own file name, so a merge names the files it
    /// rewrites. Nil when no project holds this model.
    private let projectSystem: String?

    /// Where a double-click on a palette row puts a component, in model
    /// coordinates. A drag from the palette uses the drop point instead.
    static let defaultDropPoint = (x: 80.0, y: 80.0)

    init(
        useCases: UseCaseFactory,
        clipboard: Clipboard = SystemClipboard(),
        projectRoot: String? = nil,
        projectSystem: String? = nil
    ) {
        self.useCases = useCases
        self.clipboard = clipboard
        self.projectRoot = projectRoot
        self.projectSystem = projectSystem
        threatChoices = useCases.listThreatChoices().execute(ListThreatChoicesRequest()).threats
        refresh()
    }

    /// What the palette's User row drags. No technology id reads this way, so
    /// the drop tells a user from a technology by the word alone.
    static let userDropId = "palette:user"

    func add(technologyId: String, x: Double, y: Double) {
        // The palette's User row drops through the same path a technology
        // row drops through, and adds a user rather than a component.
        if technologyId == Self.userDropId {
            addUser(x: x, y: y)
            return
        }
        // Sensitivity is fixed until a later milestone gives the user a
        // control for it.
        let response = useCases.addComponent().execute(
            AddComponentRequest(technologyId: technologyId, x: x, y: y, sensitivity: "internal")
        )

        switch response {
        case .added:
            errorMessage = nil
        case .unknownTechnology:
            errorMessage = "That technology is not in the catalogue."
        case .unknownSensitivity:
            errorMessage = "That data sensitivity is not recognised."
        }

        refresh()
    }

    /// Puts a user on the diagram: a human with no technology, drawn with the
    /// actor shape. The save writes a `user` block.
    func addUser(x: Double, y: Double) {
        _ = useCases.addUser().execute(AddUserRequest(x: x, y: y))
        errorMessage = nil
        refresh()
    }

    /// Adds a component at the default drop point, stepped so repeated
    /// double-clicks do not stack one component on another.
    func addAtDefaultPoint(technologyId: String) {
        let step = Double(canvas.components.count % 8) * 32
        add(
            technologyId: technologyId,
            x: Self.defaultDropPoint.x + step,
            y: Self.defaultDropPoint.y + step
        )
    }

    func move(_ moves: [ComponentMove]) {
        switch useCases.moveComponents().execute(MoveComponentsRequest(moves: moves)) {
        case .moved:
            errorMessage = nil
        case .unknownComponent:
            errorMessage = "That component is no longer on the model."
        }

        refresh()
    }

    func connect(sourceComponentId: String, targetComponentId: String) {
        let response = useCases.connectComponents().execute(
            ConnectComponentsRequest(
                sourceComponentId: sourceComponentId,
                targetComponentId: targetComponentId
            )
        )

        switch response {
        case .connected:
            errorMessage = nil
        // The canvas already shows the user that nothing new was drawn, so
        // neither refusal needs a message.
        case .duplicateConnection, .selfConnection:
            errorMessage = nil
        case .unknownComponent:
            errorMessage = "That component is no longer on the model."
        }

        refresh()
    }

    /// Returns what left the model so the canvas can drop those rows from its
    /// selection.
    @discardableResult
    func removeComponents(_ componentIds: [String]) -> (componentIds: [String], connectionIds: [String]) {
        let response = useCases.removeComponents().execute(
            RemoveComponentsRequest(componentIds: componentIds)
        )

        defer { refresh() }

        switch response {
        case .removed(let removedComponents, let removedConnections):
            errorMessage = nil
            return (removedComponents, removedConnections)
        case .unknownComponent:
            errorMessage = "That component is no longer on the model."
            return ([], [])
        }
    }

    func removeConnection(_ connectionId: String) {
        switch useCases.removeConnection().execute(
            RemoveConnectionRequest(connectionId: connectionId)
        ) {
        case .removed:
            errorMessage = nil
        case .unknownConnection:
            errorMessage = "That connection is no longer on the model."
        }

        refresh()
    }

    /// Returns the new zone's identifier, or nil when the drag was too small
    /// to make a zone.
    @discardableResult
    func addZone(x: Double, y: Double, width: Double, height: Double) -> String? {
        defer { refresh() }

        switch useCases.addZone().execute(
            AddZoneRequest(x: x, y: y, width: width, height: height)
        ) {
        case .added(let zoneId):
            errorMessage = nil
            return zoneId
        case .tooSmall:
            errorMessage = "That zone is too small to draw."
            return nil
        }
    }

    func resizeZone(_ zoneId: String, x: Double, y: Double, width: Double, height: Double) {
        switch useCases.resizeZone().execute(
            ResizeZoneRequest(zoneId: zoneId, x: x, y: y, width: width, height: height)
        ) {
        case .resized:
            errorMessage = nil
        case .unknownZone:
            errorMessage = "That zone is no longer on the model."
        case .tooSmall:
            errorMessage = "That zone is too small to draw."
        }

        refresh()
    }

    func setZoneProperties(
        zoneId: String,
        name: String?,
        networkZoneId: String,
        networkTypeId: String,
        riskReductionEnabled: Bool,
        riskReductionPercent: Int,
        boundaryId: String
    ) {
        switch useCases.setZoneProperties().execute(
            SetZonePropertiesRequest(
                zoneId: zoneId,
                name: name,
                networkZone: networkZoneId,
                networkType: networkTypeId,
                riskReductionEnabled: riskReductionEnabled,
                riskReductionPercent: riskReductionPercent,
                boundary: boundaryId
            )
        ) {
        case .updated:
            errorMessage = nil
        case .unknownZone:
            errorMessage = "That zone is no longer on the model."
        case .unknownNetworkZone:
            errorMessage = "That kind of zone is not recognised."
        case .unknownNetworkType:
            errorMessage = "That network type is not recognised."
        case .reductionOutOfRange:
            errorMessage = "Risk reduction must be between 0 and 100 per cent."
        case .unknownBoundary:
            errorMessage = "That boundary is not recognised."
        }

        refresh()
    }

    /// Writes what the flow panel shows. One call for the kind and the
    /// description.
    /// Writes a flow's label, and nothing else. The canvas edits this one
    /// field, so editing a label cannot change the flow's kind by accident.
    func labelConnection(connectionId: String, label: String) {
        switch useCases.labelConnection().execute(
            LabelConnectionRequest(connectionId: connectionId, label: label)
        ) {
        case .labelled:
            errorMessage = nil
        case .unknownConnection:
            errorMessage = "That flow is no longer on the model."
        }

        refresh()
    }

    /// Turns a flow round, keeping its kind and its label.
    func reverseConnection(_ connectionId: String) {
        switch useCases.reverseConnection().execute(
            ReverseConnectionRequest(connectionId: connectionId)
        ) {
        case .reversed:
            errorMessage = nil
        case .unknownConnection:
            errorMessage = "That flow is no longer on the model."
        case .alreadyConnected:
            errorMessage = "This model already holds a flow the other way round."
        }

        refresh()
    }

    func setConnectionProperties(connectionId: String, kind: String, description: String?) {
        switch useCases.setConnectionProperties().execute(
            SetConnectionPropertiesRequest(connectionId: connectionId, kind: kind, description: description)
        ) {
        case .updated:
            errorMessage = nil
        case .unknownConnection:
            errorMessage = "That flow is no longer on the model."
        case .unknownKind:
            errorMessage = "That kind of flow is not recognised."
        }

        refresh()
    }

    /// Moves every named zone as one change, so one undo takes the whole
    /// move back.
    func moveZones(_ moves: [ZoneMove]) {
        switch useCases.moveZones().execute(MoveZonesRequest(moves: moves)) {
        case .moved:
            errorMessage = nil
        case .unknownZone:
            errorMessage = "That zone is no longer on the model."
        }

        refresh()
    }

    /// Puts the named zones at the front or at the back of the drawing order,
    /// which decides which zone draws over which.
    func reorderZones(_ zoneIds: [String], placement: ZonePlacement) {
        switch useCases.reorderZones().execute(
            ReorderZonesRequest(zoneIds: zoneIds, placement: placement)
        ) {
        case .reordered:
            errorMessage = nil
        case .unknownZone:
            errorMessage = "That zone is no longer on the model."
        }

        refresh()
    }

    func removeZone(_ zoneId: String) {
        switch useCases.removeZone().execute(RemoveZoneRequest(zoneId: zoneId)) {
        case .removed:
            errorMessage = nil
        case .unknownZone:
            errorMessage = "That zone is no longer on the model."
        }

        refresh()
    }

    func setControl(key: String, implemented: Bool) {
        if implemented {
            _ = useCases.recordControlImplemented().execute(
                RecordControlImplementedRequest(controlKey: key)
            )
        } else {
            _ = useCases.recordControlNotImplemented().execute(
                RecordControlNotImplementedRequest(controlKey: key)
            )
        }

        errorMessage = nil
        refresh()
    }

    func overrideSeverity(overrideKey: String, severityId: String) {
        switch useCases.overrideThreatSeverity().execute(
            OverrideThreatSeverityRequest(overrideKey: overrideKey, severityId: severityId)
        ) {
        case .overridden:
            errorMessage = nil
        case .unknownSeverity:
            errorMessage = "That severity is not in the catalogue."
        }

        refresh()
    }

    func clearOverride(overrideKey: String) {
        // Clearing something that is not overridden is not worth a message: the
        // card only offers the command when there is an override to clear.
        _ = useCases.clearSeverityOverride().execute(
            ClearSeverityOverrideRequest(overrideKey: overrideKey)
        )

        errorMessage = nil
        refresh()
    }

    func setPathwayMaster(_ isEnabled: Bool) {
        apply(
            ConfigurePathwayMitigationsRequest(
                isMasterEnabled: isEnabled,
                mitigationId: nil,
                isEnabled: true,
                mode: PathwayMitigationMode.reduce.rawValue,
                reductionPercent: 50
            )
        )
    }

    /// Setting any one mitigation also turns the master toggle on: a user who
    /// reaches for one control means it to take effect.
    func setPathwayMitigation(id: String, isEnabled: Bool, mode: String, reductionPercent: Int) {
        apply(
            ConfigurePathwayMitigationsRequest(
                isMasterEnabled: true,
                mitigationId: id,
                isEnabled: isEnabled,
                mode: mode,
                reductionPercent: reductionPercent
            )
        )
    }

    private func apply(_ request: ConfigurePathwayMitigationsRequest) {
        switch useCases.configurePathwayMitigations().execute(request) {
        case .configured:
            errorMessage = nil
        case .unknownMitigation:
            errorMessage = "That mitigation is not in the catalogue."
        case .unknownMode:
            errorMessage = "That mitigation mode is not recognised."
        case .reductionOutOfRange:
            errorMessage = "Risk reduction must be between 0 and 100 per cent."
        }

        refresh()
    }

    var canUndo: Bool { canvas.canUndo }
    var canRedo: Bool { canvas.canRedo }

    /// What the Edit menu reads. A person who presses Undo should know what
    /// will be taken back.
    var undoTitle: String { canvas.undoLabel.map { "Undo \($0)" } ?? "Undo" }
    var redoTitle: String { canvas.redoLabel.map { "Redo \($0)" } ?? "Redo" }

    func undo() {
        // Nothing to take back is not worth a message: the menu item is
        // already dim, and a key pressed once too often is not a mistake.
        let response = useCases.undoLastChange().execute(UndoLastChangeRequest())
        errorMessage = nil
        // A merge rewrote the files as well as the model. The model's history
        // took the model back; the bytes from before the rewrite go back
        // here, before the save that follows the refresh.
        if case .undone(_, let label) = response,
           label == ChangeLabel.mergeComponents,
           let step = mergeFileSteps.popLast() {
            restore(step.before)
            undoneMergeFileSteps.append(step)
        }
        refresh()
    }

    func redo() {
        let response = useCases.redoChange().execute(RedoChangeRequest())
        errorMessage = nil
        if case .redone(_, let label) = response,
           label == ChangeLabel.mergeComponents,
           let step = undoneMergeFileSteps.popLast() {
            restore(step.after)
            mergeFileSteps.append(step)
        }
        refresh()
    }

    // MARK: merging components

    /// The bytes of the files each merge read and wrote, in merge order, so
    /// an Undo of a merge puts the files back and a Redo puts them forward.
    /// A reload from disk builds a new session and drops them.
    private var mergeFileSteps: [(before: [FileSnapshot], after: [FileSnapshot])] = []
    private var undoneMergeFileSteps: [(before: [FileSnapshot], after: [FileSnapshot])] = []

    /// Joins the draft's components into its survivor. True when the model
    /// changed. The answers the merge dropped wait in
    /// `takeDroppedMergeAnswers` for the window to report once.
    func mergeComponents(_ resolved: MergeDraft.Resolved) -> Bool {
        let response = useCases.mergeComponents().execute(
            MergeComponentsRequest(
                root: projectRoot,
                systemName: projectSystem,
                survivorId: resolved.survivorId,
                sourceIds: resolved.sourceIds,
                technologyId: resolved.technologyId,
                shape: resolved.shapeId,
                name: resolved.name,
                sensitivity: resolved.sensitivityId,
                runsAs: resolved.runsAsId,
                holds: resolved.holds,
                zoneId: resolved.zoneId,
                status: resolved.statusId,
                tags: resolved.tags,
                providedBy: resolved.providedById
            )
        )

        defer { refresh() }

        switch response {
        case .merged(let merged):
            errorMessage = nil
            droppedMergeAnswers = merged.droppedAnswers
            if merged.filesBefore.isEmpty == false {
                mergeFileSteps.append((merged.filesBefore, merged.filesAfter))
                undoneMergeFileSteps = []
            }
            return true
        case .tooFewComponents:
            errorMessage = "Select two or more components to merge."
        case .unknownComponent:
            errorMessage = "That component is no longer on the model."
        case .userCannotMerge:
            errorMessage = "A user is not a component, so it cannot be merged."
        case .unknownTechnology:
            errorMessage = "This model no longer defines that technology."
        case .unknownShape:
            errorMessage = "That shape is not one the diagram draws."
        case .unknownSensitivity:
            errorMessage = "That data sensitivity is not recognised."
        case .unknownPrivilegeLevel:
            errorMessage = "That privilege level is not recognised."
        case .unknownAsset:
            errorMessage = "This system no longer declares that asset."
        case .unknownZone:
            errorMessage = "That zone is no longer on the model."
        case .unknownStatus:
            errorMessage = "That status is not one the model holds."
        case .unknownThirdParty:
            errorMessage = "This system no longer declares that third party."
        case .noSuchSystem:
            errorMessage = "This project no longer holds that system."
        case .cannotWrite(let reason):
            errorMessage = "The merge could not be written: \(reason)"
        }
        return false
    }

    /// The answers the last merge dropped, as `<threat>@<kind>:<id>`, so the
    /// window says what went. Empty when the last merge dropped nothing.
    private(set) var droppedMergeAnswers: [String] = []

    /// Reads what the last merge dropped, and forgets it, so the window says
    /// it once.
    func takeDroppedMergeAnswers() -> [String] {
        let dropped = droppedMergeAnswers
        droppedMergeAnswers = []
        return dropped
    }

    private func restore(_ snapshots: [FileSnapshot]) {
        switch useCases.restoreFileSnapshots().execute(
            RestoreFileSnapshotsRequest(snapshots: snapshots)
        ) {
        case .restored:
            break
        case .cannotWrite(let reason):
            errorMessage = "The files could not be put back: \(reason)"
        }
    }

    func copySelection(componentIds: [String], zoneIds: [String]) {
        switch useCases.copySelection().execute(
            CopySelectionRequest(componentIds: componentIds, zoneIds: zoneIds)
        ) {
        case .copied(let payload, _, _):
            putOnClipboard(payload)
            errorMessage = nil
        case .nothingSelected:
            errorMessage = nil
        }
    }

    /// Cut is copy then delete, and the delete is what can be taken back.
    func cutSelection(componentIds: [String], zoneIds: [String]) {
        copySelection(componentIds: componentIds, zoneIds: zoneIds)
        for zoneId in zoneIds { removeZone(zoneId) }
        if componentIds.isEmpty == false { removeComponents(componentIds) }
    }

    @discardableResult
    func paste() -> (componentIds: [String], zoneIds: [String]) {
        defer { refresh() }

        guard let payload = clipboardText() else {
            errorMessage = "There is no threat model on the clipboard."
            return ([], [])
        }

        switch useCases.pasteSelection().execute(
            PasteSelectionRequest(
                payload: payload,
                offsetX: PasteSelection.defaultOffset,
                offsetY: PasteSelection.defaultOffset
            )
        ) {
        case .pasted(let componentIds, let zoneIds, let droppedControls):
            // The clipboard crosses documents, and a document names its own
            // catalogue, so a paste can carry a control answer this catalogue
            // words no control for.
            errorMessage = droppedControls.isEmpty
                ? nil
                : "\(droppedControls.count) control answers were dropped: "
                    + "this model's catalogue holds no such control."
            return (componentIds, zoneIds)
        case .nothingToPaste:
            errorMessage = nil
            return ([], [])
        case .unreadable:
            errorMessage = "There is no threat model on the clipboard."
            return ([], [])
        }
    }

    @discardableResult
    func duplicate(componentIds: [String], zoneIds: [String]) -> (componentIds: [String], zoneIds: [String]) {
        defer { refresh() }

        switch useCases.duplicateSelection().execute(
            DuplicateSelectionRequest(
                componentIds: componentIds,
                zoneIds: zoneIds,
                offsetX: PasteSelection.defaultOffset,
                offsetY: PasteSelection.defaultOffset
            )
        ) {
        case .duplicated(let componentIds, let zoneIds):
            errorMessage = nil
            return (componentIds, zoneIds)
        case .nothingSelected:
            errorMessage = nil
            return ([], [])
        }
    }

    /// The pasteboard is an IO mechanism, so it lives behind a gateway and not
    /// in the core. The payload is a string, so any other application can read
    /// it.
    func putOnClipboard(_ text: String) {
        clipboard.put(text: text)
    }

    /// Returns the new technology's identifier, or nil when the model refused
    /// the values.
    @discardableResult
    func createCustomTechnology(
        name: String,
        categoryId: String,
        description: String,
        threatIds: [String],
        enforcesEncryption: Bool,
        controls: [String] = []
    ) -> String? {
        let response = useCases.createCustomTechnology().execute(
            CreateCustomTechnologyRequest(
                name: name,
                categoryId: categoryId,
                description: description,
                threatIds: threatIds,
                enforcesEncryption: enforcesEncryption,
                controls: controls
            )
        )

        defer { refresh() }

        switch response {
        case .created(let technologyId):
            errorMessage = nil
            return technologyId
        case .emptyName:
            errorMessage = "A technology needs a name."
            return nil
        case .unknownCategory:
            errorMessage = "That category is not one this application holds."
            return nil
        case .nameAlreadyUsed(let byTechnologyId):
            errorMessage = Self.nameClash(name, with: byTechnologyId, in: self)
            return nil
        }
    }

    /// Returns true when the model took every value.
    @discardableResult
    func editCustomTechnology(
        technologyId: String,
        name: String,
        categoryId: String,
        description: String,
        threatIds: [String],
        enforcesEncryption: Bool,
        controls: [String] = []
    ) -> Bool {
        let response = useCases.editCustomTechnology().execute(
            EditCustomTechnologyRequest(
                technologyId: technologyId,
                name: name,
                categoryId: categoryId,
                description: description,
                threatIds: threatIds,
                enforcesEncryption: enforcesEncryption,
                controls: controls
            )
        )

        defer { refresh() }

        switch response {
        case .updated:
            errorMessage = nil
            return true
        case .emptyName:
            errorMessage = "A technology needs a name."
            return false
        case .unknownCategory:
            errorMessage = "That category is not one this application holds."
            return false
        case .unknownTechnology:
            errorMessage = "This model no longer defines that technology."
            return false
        case .nameAlreadyUsed(let byTechnologyId):
            errorMessage = Self.nameClash(name, with: byTechnologyId, in: self)
            return false
        }
    }

    /// Returns what left the model so the canvas can drop those rows from its
    /// selection. Deleting a technology deletes the components using it.
    @discardableResult
    func deleteCustomTechnology(
        _ technologyId: String
    ) -> (componentIds: [String], connectionIds: [String]) {
        let response = useCases.deleteCustomTechnology().execute(
            DeleteCustomTechnologyRequest(technologyId: technologyId)
        )

        defer { refresh() }

        switch response {
        case .deleted(let removedComponents, let removedConnections):
            errorMessage = nil
            return (removedComponents, removedConnections)
        case .unknownTechnology:
            errorMessage = "This model no longer defines that technology."
            return ([], [])
        }
    }

    /// Puts a different technology on a component that is already drawn.
    ///
    /// The component keeps its id, its name, its place, its zone and its
    /// flows. An answer on a threat the new technology no longer raises is
    /// dropped, and the diagnostics strip names each threat that went.
    func changeTechnology(componentId: String, technologyId: String) {
        switch useCases.changeComponentTechnology().execute(
            ChangeComponentTechnologyRequest(
                componentId: componentId,
                technologyId: technologyId
            )
        ) {
        case .changed(let dropped):
            errorMessage = nil
            droppedAnswerThreatIds = dropped
        case .unchanged:
            errorMessage = nil
        case .unknownComponent:
            errorMessage = "That component is no longer on the model."
        case .unknownTechnology:
            errorMessage = "This model no longer defines that technology."
        }

        refresh()
    }

    /// The threats whose answers the last technology change dropped, so the
    /// window says what went. Empty when the last change dropped nothing.
    private(set) var droppedAnswerThreatIds: [String] = []

    /// Reads what the last technology change dropped, and forgets it, so the
    /// window says it once.
    func takeDroppedAnswerThreatIds() -> [String] {
        let dropped = droppedAnswerThreatIds
        droppedAnswerThreatIds = []
        return dropped
    }

    /// Every technology a person can put on a component, grouped the way the
    /// palette groups them.
    var technologyChoices: [(provider: String, technologies: [(id: String, label: String)])] {
        palette.map { provider in
            (
                provider: provider.displayName,
                technologies: provider.categories.flatMap { category in
                    category.technologies.map { (id: $0.id, label: $0.name) }
                }
            )
        }
    }

    /// How this project names the sensitivity of what a component holds. The
    /// standard four unless a library states its own scheme.
    var classificationChoices: [(id: String, label: String)] {
        useCases.listClassifications().execute(ListClassificationsRequest()).classifications
            .map { (id: $0.id, label: $0.label) }
    }

    /// What the technology editor offers as a category, taken from the
    /// taxonomy, so a category nothing is in yet is still offered.
    var categoryChoices: [(id: String, label: String)] {
        useCases.listCategories().execute(ListCategoriesRequest()).categories
            .map { (id: $0.id, label: $0.label) }
    }

    /// What the editor says when two technologies would share a name.
    private static func nameClash(
        _ name: String,
        with technologyId: String,
        in session: ThreatModelSession
    ) -> String {
        let other = session.customTechnology(technologyId)?.name ?? technologyId
        return "This model already defines \"\(other)\", so \"\(name)\" is taken."
    }

    /// The technology this model defines with that identifier, or nil.
    func customTechnology(_ technologyId: String) -> ViewedCustomTechnology? {
        guard case .found(let technology) = useCases.viewCustomTechnology().execute(
            ViewCustomTechnologyRequest(technologyId: technologyId)
        ) else { return nil }
        return technology
    }

    /// How a report export resolved the project's template.
    private enum TemplateResolution {
        case none
        case found(ReportTemplate, path: String)
        case failed
    }

    /// The template the project states, read when a report is written, the
    /// way `threatmodeller report` reads it. A failure sets `errorMessage`,
    /// and the export writes nothing, the way the command line stops the run.
    private func projectTemplate() -> TemplateResolution {
        guard let projectRoot else { return .none }
        switch useCases.readReportTemplate()
            .execute(ReadReportTemplateRequest(root: projectRoot)) {
        case .none:
            return .none
        case .found(let template, let path):
            return .found(template, path: path)
        case .missing(let path):
            errorMessage = "There is no template at \(path)."
            return .failed
        case .didNotParse(let path, let diagnostics):
            errorMessage = diagnostics.map { $0.described(in: path) }.joined(separator: "\n")
            return .failed
        }
    }

    /// What a report writes, and what to call the file, or nil when the
    /// project's template stops the export. Nothing here touches the file
    /// system: the exporter asks the user where it goes.
    func markdownExport() -> (data: Data, fileName: String)? {
        let template: ReportTemplate?
        switch projectTemplate() {
        case .failed: return nil
        case .none: template = nil
        case .found(let found, _): template = found
        }
        let response = useCases.exportModelAsMarkdown()
            .execute(ExportModelAsMarkdownRequest(template: template))
        return (Data(response.markdown.utf8), response.fileName)
    }

    /// What the Report stage draws: the report as sections, in the order the
    /// project's template names them.
    ///
    /// It reads the template through `ReadReportTemplate` and the report
    /// through `BuildThreatModelReport`, which are the two use cases the
    /// exporters run, so the stage and the file cannot drift. It writes
    /// nothing and it sets no error: a template fault travels on the page.
    func reportStagePage() -> ReportStagePage {
        var template = ExportModelAsMarkdown.defaultTemplate
        var path: String?

        if let projectRoot {
            switch useCases.readReportTemplate()
                .execute(ReadReportTemplateRequest(root: projectRoot)) {
            case .none:
                break
            case .found(let found, let readFrom):
                template = found
                path = readFrom
            case .missing(let missing):
                return ReportStagePage(
                    sections: [],
                    templatePath: missing,
                    fault: ["There is no template at \(missing)."]
                )
            case .didNotParse(let didNotParse, let diagnostics):
                return ReportStagePage(
                    sections: [],
                    templatePath: didNotParse,
                    fault: diagnostics.map { $0.described(in: didNotParse) }
                )
            }
        }

        let report = useCases.buildThreatModelReport()
            .execute(BuildThreatModelReportRequest()).report
        return ReportStagePage(
            sections: ReportStagePage.build(report: report, template: template),
            templatePath: path
        )
    }

    /// The report the stage draws its numbers from.
    func builtReport() -> Report {
        useCases.buildThreatModelReport().execute(BuildThreatModelReportRequest()).report
    }

    /// The report as one page, with every picture inside it.
    ///
    /// The pictures are the ones the command line tool draws, from the same
    /// code, so the page a person exports and the page a build writes are the
    /// same page.
    func htmlExport() -> (data: Data, fileName: String)? {
        let template: ReportTemplate?
        switch projectTemplate() {
        case .failed: return nil
        case .none: template = nil
        case .found(let found, _): template = found
        }
        let assessment = useCases.assessThreatModel().execute(AssessThreatModelRequest())
        let report = useCases.buildThreatModelReport()
            .execute(BuildThreatModelReportRequest()).report
        let drawn = DiagramBuilder.Model(
            components: canvas.components,
            connections: canvas.connections,
            zones: canvas.zones,
            risks: ElementRiskRollup.byElement(
                assessment.threats,
                levelOrder: assessment.severities.map(\.id)
            ),
            guards: EdgeGuards.byElement(assessment.threats)
        )
        let stem = FileNaming.stem(from: report.modelName)
        let threats = ThreatDiagrams.pictures(
            of: drawn,
            for: report.rollups.topResidual,
            stem: stem
        )
        let controls = ThreatDiagrams.controlPictures(
            of: drawn,
            for: report.protectionDependencies,
            stem: stem
        )

        var sources = Dictionary(uniqueKeysWithValues: threats.map { ($0.fileName, $0.svg) })
        for picture in controls { sources[picture.fileName] = picture.svg }

        let page = useCases.exportModelAsHtml().execute(
            ExportModelAsHtmlRequest(
                threatPictures: Dictionary(
                    uniqueKeysWithValues: threats.map { ($0.key, $0.fileName) }
                ),
                controlPictures: Dictionary(
                    uniqueKeysWithValues: controls.map { ($0.protectorId, $0.fileName) }
                ),
                pictureSources: sources,
                wholePicture: SvgWriter.svg(of: DiagramBuilder.drawing(of: drawn)),
                template: template
            )
        )
        return (Data(page.html.utf8), page.fileName)
    }

    /// The assessed model as data another program reads. The same use case
    /// the executable's `export` verb runs, so a file written from the window
    /// and a file written from a build hold the same shape.
    func jsonExport() -> (data: Data, fileName: String) {
        let response = useCases.exportModelAsJson().execute(ExportModelAsJsonRequest())
        return (Data(response.json.utf8), response.fileName)
    }

    /// The assessed model in the Open Threat Model shape, which other
    /// threat-modelling tools read. The same use case the executable's
    /// `export --format otm` verb runs, so a file written from the window and
    /// a file written from a build hold the same shape.
    func otmExport() -> (data: Data, fileName: String) {
        let response = useCases.exportModelAsOtm().execute(ExportModelAsOtmRequest())
        return (Data(response.json.utf8), response.fileName)
    }

    /// The diagram as Mermaid text, which a wiki renders and a reviewer
    /// reads in a diff.
    func mermaidExport() -> (data: Data, fileName: String) {
        let assessment = useCases.assessThreatModel().execute(AssessThreatModelRequest())
        let drawn = DiagramBuilder.Model(
            components: canvas.components,
            connections: canvas.connections,
            zones: canvas.zones,
            risks: ElementRiskRollup.byElement(
                assessment.threats,
                levelOrder: assessment.severities.map(\.id)
            ),
            guards: EdgeGuards.byElement(assessment.threats)
        )
        let text = TextDiagramWriter.mermaid(of: drawn)
        return (Data(text.utf8), "\(FileNaming.stem(from: canvas.name)).mmd")
    }

    /// The diagram as Graphviz DOT text, which Graphviz draws. The same
    /// writer the executable's `draw --dot` verb runs.
    func dotExport() -> (data: Data, fileName: String) {
        let assessment = useCases.assessThreatModel().execute(AssessThreatModelRequest())
        let drawn = DiagramBuilder.Model(
            components: canvas.components,
            connections: canvas.connections,
            zones: canvas.zones,
            risks: ElementRiskRollup.byElement(
                assessment.threats,
                levelOrder: assessment.severities.map(\.id)
            ),
            guards: EdgeGuards.byElement(assessment.threats)
        )
        let text = TextDiagramWriter.dot(of: drawn)
        return (Data(text.utf8), "\(FileNaming.stem(from: canvas.name)).dot")
    }

    /// The diagram as D2 text, which D2 draws. The same writer the
    /// executable's `draw --d2` verb runs.
    func d2Export() -> (data: Data, fileName: String) {
        let assessment = useCases.assessThreatModel().execute(AssessThreatModelRequest())
        let drawn = DiagramBuilder.Model(
            components: canvas.components,
            connections: canvas.connections,
            zones: canvas.zones,
            risks: ElementRiskRollup.byElement(
                assessment.threats,
                levelOrder: assessment.severities.map(\.id)
            ),
            guards: EdgeGuards.byElement(assessment.threats)
        )
        let text = TextDiagramWriter.d2(of: drawn)
        return (Data(text.utf8), "\(FileNaming.stem(from: canvas.name)).d2")
    }

    func threatclExport() -> (data: Data, fileName: String) {
        let response = useCases.exportModelAsThreatcl().execute(ExportModelAsThreatclRequest())
        return (Data(response.hcl.utf8), response.fileName)
    }

    /// The report page, printed. Returns nil when the page could not print,
    /// and says so in `errorMessage`.
    func pdfExport() async -> (data: Data, fileName: String)? {
        guard let page = htmlExport() else { return nil }
        do {
            let data = try await HtmlPdfPrinter().pdf(
                fromHtml: String(decoding: page.data, as: UTF8.self)
            )
            errorMessage = nil
            return (data, page.fileName.replacingOccurrences(of: ".html", with: ".pdf"))
        } catch {
            errorMessage = "The report could not be printed: \(String(describing: error))"
            return nil
        }
    }

    /// What the picture should draw, for the delivery mechanism's renderer.
    func imageArea() -> ExportModelAsImageResponse {
        useCases.exportModelAsImage().execute(ExportModelAsImageRequest())
    }

    /// Puts a picture of the diagram on the clipboard, as PNG and as PDF.
    ///
    /// With elements named, the picture holds those elements and the flows
    /// between them, cropped to their bounds with a margin. With none named,
    /// it holds the whole diagram, the same area the image export writes.
    /// It answers false when the model holds nothing to draw.
    @discardableResult
    func copyDiagramAsImage(componentIds: [String] = [], zoneIds: [String] = []) -> Bool {
        let whole = imageArea()
        let picked = Set(componentIds)
        let pickedZones = Set(zoneIds)

        var drawn = canvas
        var area = whole

        if picked.isEmpty == false || pickedZones.isEmpty == false {
            let components = canvas.components.filter { picked.contains($0.id) }
            let zones = canvas.zones.filter { pickedZones.contains($0.id) }
            guard let rect = SelectionBounds.rect(
                components: components.map {
                    ($0.x, $0.y, Component.size.width, Component.size.height)
                },
                zones: zones.map { ($0.x, $0.y, $0.width, $0.height) }
            ) else { return false }

            drawn = ViewThreatModelResponse(
                name: canvas.name,
                components: components,
                connections: canvas.connections.filter {
                    picked.contains($0.sourceComponentId) && picked.contains($0.targetComponentId)
                },
                zones: zones
            )
            area = ExportModelAsImageResponse(
                fileName: whole.fileName,
                x: rect.minX,
                y: rect.minY,
                width: rect.width,
                height: rect.height,
                isEmpty: false
            )
        }

        guard area.isEmpty == false else {
            errorMessage = "There is nothing on the diagram to copy."
            return false
        }

        do {
            let renderer = CanvasImageRenderer()
            let png = try renderer.png(
                of: drawn,
                risks: elementRisks,
                guards: elementGuards,
                area: area
            )
            let pdf = try renderer.pdf(
                of: drawn,
                risks: elementRisks,
                guards: elementGuards,
                area: area
            )
            clipboard.put(png: png, pdf: pdf)
            errorMessage = nil
            return true
        } catch {
            errorMessage = "The picture could not be drawn: \(String(describing: error))"
            return false
        }
    }

    /// Said when an export could not be written.
    func reportExportFailed(_ reason: String) {
        errorMessage = "The export could not be written: \(reason)"
    }

    /// Writes what the node panel shows. One call for the name, the
    /// sensitivity, the shape and whether the node raises threats at all.
    /// Writes what the user panel shows: the name, the role, the access, the
    /// reaches and the threat actor the user is.
    func setUserProperties(
        componentId: String,
        name: String?,
        role: String,
        accessId: String,
        reaches: [String],
        threatActorId: String?
    ) {
        switch useCases.setUserProperties().execute(
            SetUserPropertiesRequest(
                componentId: componentId,
                name: name,
                role: role,
                access: accessId,
                reaches: reaches,
                threatActorId: threatActorId
            )
        ) {
        case .updated:
            errorMessage = nil
        case .unknownUser:
            errorMessage = "That user is no longer on the model."
        case .unknownAccessLevel:
            errorMessage = "That access level is not recognised."
        case .unknownComponent(let id):
            errorMessage = "This model holds no component called \"\(id)\"."
        case .unknownActor(let id):
            errorMessage = "This project holds no threat actor called \"\(id)\"."
        }

        refresh()
    }

    func setComponentProperties(
        componentId: String,
        name: String?,
        sensitivityId: String,
        threatsDisabled: Bool,
        runsAsId: String,
        shapeId: String? = nil,
        holds: [String]? = nil,
        tags: [String]? = nil,
        status: String? = nil,
        version: String? = nil,
        cves: [String]? = nil
    ) {
        switch useCases.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: componentId,
                name: name,
                sensitivity: sensitivityId,
                threatsDisabled: threatsDisabled,
                runsAs: runsAsId,
                shape: shapeId,
                holds: holds,
                tags: tags,
                status: status,
                version: version,
                cves: cves
            )
        ) {
        case .updated:
            errorMessage = nil
        case .unknownComponent:
            errorMessage = "That component is no longer on the model."
        case .unknownSensitivity:
            errorMessage = "That sensitivity is not one this application holds."
        case .unknownPrivilegeLevel:
            errorMessage = "That privilege level is not recognised."
        case .unknownShape:
            errorMessage = "That shape is not one this application holds."
        case .unknownAsset:
            errorMessage = "This system declares no such asset."
        case .notACveId(let word):
            errorMessage = "\"\(word)\" is not a CVE id. A CVE id reads CVE-<year>-<number>."
        }

        refresh()
    }

    /// Writes what the four-way status control says. `implemented` records the
    /// control, exactly as the checkbox did.
    func setControlStatus(key: String, statusId: String) {
        useCases.setControlStatus().execute(
            SetControlStatusRequest(controlKey: key, statusId: statusId)
        ).describe(into: &errorMessage)
        refresh()
    }

    /// Writes what proves one control is in place. Everything empty clears it.
    func setControlEvidence(
        key: String,
        evidenceId: String?,
        reference: String,
        verifiedOn: String?
    ) {
        useCases.setControlEvidence().execute(
            SetControlEvidenceRequest(
                controlKey: key,
                evidenceId: evidenceId,
                reference: reference,
                verifiedOn: verifiedOn
            )
        ).describe(into: &errorMessage)
        refresh()
    }

    /// Adds or replaces what compensates one threat. An empty label removes it.
    func setCompensatingControl(
        threatKey: String,
        label: String,
        reducesRiskBy: Int,
        rationale: String,
        evidenceId: String? = nil,
        evidenceReference: String = "",
        verifiedOn: String? = nil
    ) {
        useCases.setCompensatingControl().execute(
            SetCompensatingControlRequest(
                threatKey: threatKey,
                label: label,
                reducesRiskBy: reducesRiskBy,
                rationale: rationale,
                evidenceId: evidenceId,
                evidenceReference: evidenceReference,
                verifiedOn: verifiedOn
            )
        ).describe(into: &errorMessage)
        refresh()
    }

    // MARK: the risk level a likelihood finding may answer up to

    /// States the level: `low`, `medium`, `high` or `critical`. The value
    /// `canvas.riskTolerance` reads changes on the same refresh.
    func setRiskTolerance(_ level: String) {
        useCases.setRiskTolerance()
            .execute(SetRiskToleranceRequest(level: level))
            .describe(into: &errorMessage)
        refresh()
    }

    // MARK: what the system takes on trust

    /// Writes down a fact the team accepts without proof, or changes the one
    /// this label already names.
    func setAssumption(label: String, text: String, owner: String?) {
        useCases.setAssumption()
            .execute(SetAssumptionRequest(label: label, text: text, owner: owner))
            .describe(into: &errorMessage)
        refresh()
    }

    func removeAssumption(label: String) {
        useCases.removeAssumption()
            .execute(RemoveAssumptionRequest(label: label))
            .describe(into: &errorMessage)
        refresh()
    }

    // MARK: the named things of value the system holds

    func setSystemAsset(
        id: String,
        name: String,
        classificationId: String,
        description: String = "",
        owner: String? = nil
    ) {
        useCases.setSystemAsset()
            .execute(
                SetSystemAssetRequest(
                    id: id,
                    name: name,
                    classification: classificationId,
                    description: description,
                    owner: owner
                )
            )
            .describe(into: &errorMessage)
        refresh()
    }

    func removeSystemAsset(id: String) {
        useCases.removeSystemAsset()
            .execute(RemoveSystemAssetRequest(id: id))
            .describe(into: &errorMessage)
        refresh()
    }

    func setConnectionAssets(connectionId: String, carries: [String]) {
        useCases.setConnectionAssets()
            .execute(SetConnectionAssetsRequest(connectionId: connectionId, carries: carries))
            .describe(into: &errorMessage)
        refresh()
    }

    // MARK: what this document states about itself

    /// Writes the document-control attributes of the `system` block. A nil
    /// field leaves what the model states; an empty one clears the attribute.
    func setSystemFacts(
        owner: String? = nil,
        description: String? = nil,
        authors: [String]? = nil,
        version: String? = nil,
        created: String? = nil,
        reviewed: String? = nil,
        links: [String]? = nil,
        repositories: [String]? = nil
    ) {
        useCases.setSystemFacts()
            .execute(
                SetSystemFactsRequest(
                    owner: owner,
                    description: description,
                    authors: authors,
                    version: version,
                    created: created,
                    reviewed: reviewed,
                    links: links,
                    repositories: repositories
                )
            )
            .describe(into: &errorMessage)
        refresh()
    }

    /// Writes one free-form `attribute` block. Writing the same name again
    /// changes the block that is there.
    func setSystemAttribute(name: String, value: String) {
        useCases.setSystemAttribute()
            .execute(SetSystemAttributeRequest(name: name, value: value))
            .describe(into: &errorMessage)
        refresh()
    }

    /// Takes one free-form `attribute` block off.
    func removeSystemAttribute(name: String) {
        useCases.removeSystemAttribute()
            .execute(RemoveSystemAttributeRequest(name: name))
            .describe(into: &errorMessage)
        refresh()
    }

    // MARK: the pictures a team keeps beside the diagram the canvas draws

    /// Writes one `diagram` block. Writing the same label again changes the
    /// block that is there.
    func setSystemDiagram(label: String, text: String) {
        useCases.setSystemDiagram()
            .execute(SetSystemDiagramRequest(label: label, text: text))
            .describe(into: &errorMessage)
        refresh()
    }

    /// Takes one `diagram` block off.
    func removeSystemDiagram(label: String) {
        useCases.removeSystemDiagram()
            .execute(RemoveSystemDiagramRequest(label: label))
            .describe(into: &errorMessage)
        refresh()
    }

    // MARK: the parties outside this team the system depends on

    /// Writes one `third_party` block into this system's file. Writing the
    /// same id again changes the block that is there.
    func setThirdParty(
        id: String,
        name: String,
        description: String = "",
        kindId: String = "saas",
        payingCustomer: Bool = false,
        uptimeId: String = "none",
        uptimeNotes: String = "",
        owner: String? = nil,
        link: String? = nil
    ) {
        useCases.setThirdParty()
            .execute(
                SetThirdPartyRequest(
                    id: id,
                    name: name,
                    description: description,
                    kind: kindId,
                    payingCustomer: payingCustomer,
                    uptime: uptimeId,
                    uptimeNotes: uptimeNotes,
                    owner: owner,
                    link: link
                )
            )
            .describe(into: &errorMessage)
        refresh()
    }

    /// Takes one `third_party` block off. A component that names the party
    /// refuses the removal, and the message names that component.
    func removeThirdParty(id: String) {
        useCases.removeThirdParty()
            .execute(RemoveThirdPartyRequest(id: id))
            .describe(into: &errorMessage)
        refresh()
    }

    /// States which third party provides one component. Nil states that no
    /// party provides it.
    func setComponentProvider(componentId: String, thirdPartyId: String?) {
        useCases.setComponentProvider()
            .execute(
                SetComponentProviderRequest(
                    componentId: componentId,
                    thirdPartyId: thirdPartyId
                )
            )
            .describe(into: &errorMessage)
        refresh()
    }

    // MARK: what the model covers and what it leaves out

    func setSystemUseCase(label: String, text: String) {
        useCases.setSystemUseCase()
            .execute(SetSystemUseCaseRequest(label: label, text: text))
            .describe(into: &errorMessage)
        refresh()
    }

    func removeSystemUseCase(label: String) {
        useCases.removeSystemUseCase()
            .execute(RemoveSystemUseCaseRequest(label: label))
            .describe(into: &errorMessage)
        refresh()
    }

    func setExclusion(label: String, text: String, rationale: String) {
        useCases.setExclusion()
            .execute(SetExclusionRequest(label: label, text: text, rationale: rationale))
            .describe(into: &errorMessage)
        refresh()
    }

    func removeExclusion(label: String) {
        useCases.removeExclusion()
            .execute(RemoveExclusionRequest(label: label))
            .describe(into: &errorMessage)
        refresh()
    }

    // MARK: the adversaries this system faces

    /// The actors this project may face, with what each one performs.
    ///
    /// Read on demand rather than held: the ATT&CK groups are parsed the first
    /// time something asks for them, and a window that never opens the actors
    /// sheet must not pay for that.
    var threatActorsInUse: [ListedThreatActor] {
        useCases.listThreatActorsInUse()
            .execute(ListThreatActorsInUseRequest())
            .actors
    }

    /// States which actors this system faces. The whole list is written, so
    /// an id left out comes out of the file.
    func setFacedThreatActors(_ actorIds: [String]) {
        useCases.setFacedThreatActors()
            .execute(SetFacedThreatActorsRequest(actorIds: actorIds))
            .describe(into: &errorMessage)
        refresh()
    }

    /// Writes one `threat_actor` block into this system's file. Writing the
    /// same id again changes the block that is there.
    func setLocalThreatActor(
        id: String,
        name: String,
        description: String = "",
        aliases: [String] = [],
        capability: String? = nil,
        intent: String = "",
        performs: [String] = [],
        techniques: [String] = [],
        performsCatalogueTier: String? = nil
    ) {
        useCases.setLocalThreatActor()
            .execute(
                SetLocalThreatActorRequest(
                    id: id,
                    name: name,
                    description: description,
                    aliases: aliases,
                    capability: capability,
                    intent: intent,
                    performs: performs,
                    techniques: techniques,
                    performsCatalogueTier: performsCatalogueTier
                )
            )
            .describe(into: &errorMessage)
        refresh()
    }

    func removeLocalThreatActor(id: String) {
        useCases.removeLocalThreatActor()
            .execute(RemoveLocalThreatActorRequest(id: id))
            .describe(into: &errorMessage)
        refresh()
    }

    // MARK: what one component lowers on another

    /// States that one component lowers a named threat set on another. The two
    /// ends name the edge, so writing between the same two changes it.
    func setMitigatesEdge(
        from sourceComponentId: String,
        to targetComponentId: String,
        threatIds: [String],
        reducesRiskBy: Int,
        status: String,
        actionLabel: String? = nil,
        actionText: String? = nil,
        actionNote: String? = nil,
        blockedBy: String? = nil,
        sources: [String] = []
    ) {
        let action = actionLabel.map {
            SetMitigatesEdgeRequest.Action(
                label: $0,
                text: actionText,
                note: actionNote,
                blockedBy: blockedBy,
                sources: sources
            )
        }
        useCases.setMitigatesEdge()
            .execute(
                SetMitigatesEdgeRequest(
                    sourceComponentId: sourceComponentId,
                    targetComponentId: targetComponentId,
                    threatIds: threatIds,
                    reducesRiskBy: reducesRiskBy,
                    status: status,
                    action: action
                )
            )
            .describe(into: &errorMessage)
        refresh()
    }

    func removeMitigatesEdge(from sourceComponentId: String, to targetComponentId: String) {
        useCases.removeMitigatesEdge()
            .execute(
                RemoveMitigatesEdgeRequest(
                    sourceComponentId: sourceComponentId,
                    targetComponentId: targetComponentId
                )
            )
            .describe(into: &errorMessage)
        refresh()
    }

    // MARK: how often a threat happens

    /// Records what a person learned about how often an attack of this kind
    /// happens. A threat holds one finding, so this changes the one it has.
    func setLikelihoodFinding(
        threatKey: String,
        label: String,
        tier: String?,
        prior: Int?,
        rationale: String,
        sources: [String]
    ) {
        useCases.setLikelihoodFinding()
            .execute(
                SetLikelihoodFindingRequest(
                    threatKey: threatKey,
                    label: label,
                    tier: tier,
                    prior: prior,
                    rationale: rationale,
                    sources: sources
                )
            )
            .describe(into: &errorMessage)
        refresh()
    }

    func removeLikelihoodFinding(threatKey: String) {
        useCases.removeLikelihoodFinding()
            .execute(RemoveLikelihoodFindingRequest(threatKey: threatKey))
            .describe(into: &errorMessage)
        refresh()
    }

    /// The examples the File menu offers.
    var samples: [ListedSample] {
        useCases.listSampleModels().execute(ListSampleModelsRequest()).samples
    }

    /// Puts an example in front of the user. One change, so one undo takes it
    /// back.
    /// The picture of one example, or nil when it cannot be read. Nothing on
    /// screen changes: the browser draws this beside the sample's name.
    func samplePicture(_ sampleId: String) -> ViewThreatModelResponse? {
        guard case .drawn(let drawn) = useCases.previewSampleModel().execute(
            PreviewSampleModelRequest(sampleId: sampleId)
        ) else { return nil }
        return drawn
    }

    func loadSample(_ sampleId: String) {
        switch useCases.loadSampleModel().execute(LoadSampleModelRequest(sampleId: sampleId)) {
        case .loaded:
            errorMessage = nil
        case .unknownSample:
            errorMessage = "This application no longer holds that example."
        case .unreadable(let reason):
            errorMessage = "That example could not be opened: \(reason)"
        }

        // A model that has just loaded is worst first.
        resortThreats()
    }

    /// Opens or closes one group.
    ///
    /// `appliesToEveryGroup` is what an option-click means, the way Finder
    /// reads one: closing a group with the key held closes every group, and
    /// opening one opens every group.
    func toggleGroup(
        _ id: String,
        everyGroupId: [String] = [],
        appliesToEveryGroup: Bool = false
    ) {
        let isCollapsed = collapsedGroups.contains(id)
        guard appliesToEveryGroup else {
            if isCollapsed { collapsedGroups.remove(id) } else { collapsedGroups.insert(id) }
            return
        }
        collapsedGroups = isCollapsed ? [] : Set(everyGroupId)
    }

    func collapseEveryGroup(_ ids: [String]) {
        collapsedGroups = Set(ids)
    }

    /// The element the sidebar shows the threats of, or nil for every
    /// element. A context menu sets it, and the filter bar clears it.
    private(set) var focusedElementId: String?

    /// Shows one element's threats, and opens that element's group.
    func focus(onElementId elementId: String) {
        focusedElementId = elementId
        collapsedGroups.remove(elementId)
    }

    func clearElementFocus() {
        focusedElementId = nil
    }

    func expandEveryGroup() {
        collapsedGroups = []
    }

    /// Stamps the model with the catalogue in use, so the next save writes
    /// that tag into the file.
    func adoptCatalogueVersion() {
        _ = useCases.adoptCatalogueVersion().execute(AdoptCatalogueVersionRequest())
        refresh()
    }

    /// Sorts the list worst first and hides the Reorder button.
    ///
    /// The button calls this, and so does every event that is not an edit: a
    /// model loading from disk, and the stage changing.
    func resortThreats() {
        resortsOnNextRead = true
        refresh()
    }

    /// The threats in the order the list already draws them.
    ///
    /// A threat the architecture newly raises enters at the place a sort would
    /// put it, and a threat it no longer raises leaves. Nothing else moves.
    static func held(_ assessed: [AssessedThreat], inOrderOf previous: [String]) -> [AssessedThreat] {
        let byKey = Dictionary(
            assessed.map { ($0.threatKey, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        var drawn = previous.compactMap { byKey[$0] }
        var known = Set(drawn.map(\.threatKey))

        for (index, row) in assessed.enumerated() where known.contains(row.threatKey) == false {
            let precedingDrawn = assessed.prefix(index)
                .map(\.threatKey)
                .last { known.contains($0) }
            let place = precedingDrawn
                .flatMap { key in drawn.firstIndex { $0.threatKey == key }.map { $0 + 1 } }
                ?? 0
            drawn.insert(row, at: place)
            known.insert(row.threatKey)
        }

        return drawn
    }

    /// How many rows a sort would move.
    static func rowsOutOfOrder(
        drawn: [AssessedThreat],
        sorted: [AssessedThreat]
    ) -> Int {
        zip(drawn, sorted).count { $0.threatKey != $1.threatKey }
    }

    private func clipboardText() -> String? {
        clipboard.text()
    }

    /// Spec section 2: the delivery mechanism calls `AssessThreatModel`
    /// explicitly after each change, and reads the canvas the same way.
    /// Reads the model again, after something outside this session changed
    /// it. The layout runs off the main actor and writes through the same
    /// gateway, so the session has to be told to read it back.
    func reread() {
        refresh()
    }

    private func refresh() {
        revision += 1
        palette = useCases.listTechnologies().execute(ListTechnologiesRequest()).providers
        canvas = useCases.viewThreatModel().execute(ViewThreatModelRequest())
        let assessment = useCases.assessThreatModel().execute(AssessThreatModelRequest())
        if resortsOnNextRead {
            threats = assessment.threats
            resortsOnNextRead = false
        } else {
            threats = Self.held(assessment.threats, inOrderOf: drawnOrder)
        }
        rowsOutOfOrder = Self.rowsOutOfOrder(drawn: threats, sorted: assessment.threats)
        drawnOrder = threats.map(\.threatKey)
        severityChoices = assessment.severities
        elementRisks = ElementRiskRollup.byElement(
            assessment.threats,
            levelOrder: assessment.severities.map(\.id)
        )
        elementGuards = EdgeGuards.byElement(assessment.threats)
        summary = useCases.summariseRisk().execute(SummariseRiskRequest())
        pathwayMitigations = useCases.listPathwayMitigations()
            .execute(ListPathwayMitigationsRequest())
        onChange?()
    }
}

/// What the canvas asks for when a filter or a Focus narrows the diagram.
///
/// The session already holds the canvas snapshot and the use case factory, so
/// it answers both questions the canvas asks.
extension ThreatModelSession: NarrowedDiagramLayouts {
    var model: ViewThreatModelResponse { canvas }

    func layOutSubset(componentIds: [String], zoneIds: [String]) -> LayOutSubsetResponse {
        useCases.layOutSubset().execute(
            LayOutSubsetRequest(componentIds: componentIds, zoneIds: zoneIds)
        )
    }
}
