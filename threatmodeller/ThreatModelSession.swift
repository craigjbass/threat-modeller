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
    private(set) var errorMessage: String?

    /// Where a double-click on a palette row puts a component, in model
    /// coordinates. A drag from the palette uses the drop point instead.
    static let defaultDropPoint = (x: 80.0, y: 80.0)

    init(useCases: UseCaseFactory) {
        self.useCases = useCases
        palette = useCases.listTechnologies().execute(ListTechnologiesRequest()).providers
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

    /// Spec section 2: the delivery mechanism calls `AssessThreatModel`
    /// explicitly after each change, and reads the canvas the same way.
    private func refresh() {
        canvas = useCases.viewThreatModel().execute(ViewThreatModelRequest())
        let assessment = useCases.assessThreatModel().execute(AssessThreatModelRequest())
        threats = assessment.threats
        severityChoices = assessment.severities
        summary = useCases.summariseRisk().execute(SummariseRiskRequest())
    }
}
