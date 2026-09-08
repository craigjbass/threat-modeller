import AppKit
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

    private(set) var palette: [ListedProvider] = []
    /// What the canvas draws. Spec section 9 calls this the canvas snapshot.
    private(set) var canvas = ViewThreatModelResponse(
        name: "Untitled",
        components: [],
        connections: [],
        zones: []
    )
    private(set) var threats: [AssessedThreat] = []
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

    /// Where a double-click on a palette row puts a component, in model
    /// coordinates. A drag from the palette uses the drop point instead.
    static let defaultDropPoint = (x: 80.0, y: 80.0)

    init(useCases: UseCaseFactory) {
        self.useCases = useCases
        threatChoices = useCases.listThreatChoices().execute(ListThreatChoicesRequest()).threats
        refresh()
    }

    func add(technologyId: String, x: Double, y: Double) {
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
        riskReductionPercent: Int
    ) {
        switch useCases.setZoneProperties().execute(
            SetZonePropertiesRequest(
                zoneId: zoneId,
                name: name,
                networkZone: networkZoneId,
                networkType: networkTypeId,
                riskReductionEnabled: riskReductionEnabled,
                riskReductionPercent: riskReductionPercent
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

    func undo() {
        // Nothing to take back is not worth a message: the menu item is
        // already dim, and a key pressed once too often is not a mistake.
        _ = useCases.undoLastChange().execute(UndoLastChangeRequest())
        errorMessage = nil
        refresh()
    }

    func redo() {
        _ = useCases.redoChange().execute(RedoChangeRequest())
        errorMessage = nil
        refresh()
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
        case .pasted(let componentIds, let zoneIds):
            errorMessage = nil
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

    /// The pasteboard is an IO mechanism, so it lives here and not in the core.
    /// The payload is a string, so any other application can read it.
    func putOnClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    /// Returns the new technology's identifier, or nil when the model refused
    /// the values.
    @discardableResult
    func createCustomTechnology(
        name: String,
        categoryId: String,
        description: String,
        threatIds: [String],
        enforcesEncryption: Bool
    ) -> String? {
        let response = useCases.createCustomTechnology().execute(
            CreateCustomTechnologyRequest(
                name: name,
                categoryId: categoryId,
                description: description,
                threatIds: threatIds,
                enforcesEncryption: enforcesEncryption
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
        enforcesEncryption: Bool
    ) -> Bool {
        let response = useCases.editCustomTechnology().execute(
            EditCustomTechnologyRequest(
                technologyId: technologyId,
                name: name,
                categoryId: categoryId,
                description: description,
                threatIds: threatIds,
                enforcesEncryption: enforcesEncryption
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

    /// What the technology editor offers as a category, taken from the
    /// palette so the editor names exactly what the palette can show.
    var categoryChoices: [(id: String, label: String)] {
        var seen: Set<String> = []
        var choices: [(id: String, label: String)] = []
        for provider in palette {
            for category in provider.categories where seen.contains(category.id) == false {
                seen.insert(category.id)
                choices.append((id: category.id, label: category.label))
            }
        }
        return choices.sorted { $0.label < $1.label }
    }

    /// The technology this model defines with that identifier, or nil.
    func customTechnology(_ technologyId: String) -> ViewedCustomTechnology? {
        guard case .found(let technology) = useCases.viewCustomTechnology().execute(
            ViewCustomTechnologyRequest(technologyId: technologyId)
        ) else { return nil }
        return technology
    }

    /// What a report writes, and what to call the file. Nothing here touches
    /// the file system: the exporter asks the user where it goes.
    func markdownExport() -> (data: Data, fileName: String) {
        let response = useCases.exportModelAsMarkdown().execute(ExportModelAsMarkdownRequest())
        return (Data(response.markdown.utf8), response.fileName)
    }

    func threatclExport() -> (data: Data, fileName: String) {
        let response = useCases.exportModelAsThreatcl().execute(ExportModelAsThreatclRequest())
        return (Data(response.hcl.utf8), response.fileName)
    }

    /// Returns nil when the renderer could not draw, and says so in
    /// `errorMessage`.
    func pdfExport() -> (data: Data, fileName: String)? {
        switch useCases.exportModelAsPdf().execute(ExportModelAsPdfRequest()) {
        case .exported(let bytes, let fileName):
            errorMessage = nil
            return (Data(bytes), fileName)
        case .cannotRender(let reason):
            errorMessage = "The report could not be drawn: \(reason)"
            return nil
        }
    }

    /// What the picture should draw, for the delivery mechanism's renderer.
    func imageArea() -> ExportModelAsImageResponse {
        useCases.exportModelAsImage().execute(ExportModelAsImageRequest())
    }

    /// Said when an export could not be written.
    func reportExportFailed(_ reason: String) {
        errorMessage = "The export could not be written: \(reason)"
    }

    private func clipboardText() -> String? {
        NSPasteboard.general.string(forType: .string)
    }

    /// Spec section 2: the delivery mechanism calls `AssessThreatModel`
    /// explicitly after each change, and reads the canvas the same way.
    private func refresh() {
        palette = useCases.listTechnologies().execute(ListTechnologiesRequest()).providers
        canvas = useCases.viewThreatModel().execute(ViewThreatModelRequest())
        let assessment = useCases.assessThreatModel().execute(AssessThreatModelRequest())
        threats = assessment.threats
        severityChoices = assessment.severities
        summary = useCases.summariseRisk().execute(SummariseRiskRequest())
        pathwayMitigations = useCases.listPathwayMitigations()
            .execute(ListPathwayMitigationsRequest())
    }
}
