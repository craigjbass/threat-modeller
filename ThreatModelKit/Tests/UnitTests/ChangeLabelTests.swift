import Testing
import ThreatModelKit
import TestSupport

/// Every write use case names its change, so the Edit menu reads
/// `Undo Move` rather than `Undo`.
@Suite("What each change is called")
struct ChangeLabelTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()
    private let ids = SequentialIdentityGenerator()

    private func addAComponent() -> String {
        guard case .added(let id) = AddComponent(models: models, catalogue: catalogue, ids: ids)
            .execute(
                AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "confidential")
            ) else {
            Issue.record("expected a component")
            return ""
        }
        return id
    }

    @Test func namesTheChangeEachUseCaseMakes() throws {
        let component = addAComponent()
        #expect(models.undoLabel == ChangeLabel.addComponent)

        _ = MoveComponents(models: models).execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: component, x: 40, y: 40)])
        )
        #expect(models.undoLabel == ChangeLabel.moveComponents)

        guard case .added(let zone) = AddZone(models: models, ids: ids)
            .execute(AddZoneRequest(x: 0, y: 0, width: 400, height: 400)) else {
            Issue.record("expected a zone")
            return
        }
        #expect(models.undoLabel == ChangeLabel.addZone)

        _ = RemoveZone(models: models).execute(RemoveZoneRequest(zoneId: zone))
        #expect(models.undoLabel == ChangeLabel.removeZone)

        let second = addAComponent()
        _ = ConnectComponents(models: models, ids: ids).execute(
            ConnectComponentsRequest(sourceComponentId: component, targetComponentId: second)
        )
        #expect(models.undoLabel == ChangeLabel.connectComponents)

        _ = RemoveComponents(models: models).execute(
            RemoveComponentsRequest(componentIds: [second])
        )
        #expect(models.undoLabel == ChangeLabel.removeComponents)
    }

    @Test func namesTheChangeAnAnswerMakes() throws {
        let component = addAComponent()
        let assessed = AssessThreatModel(models: models, catalogue: catalogue)
            .execute(AssessThreatModelRequest())
        let threat = try #require(assessed.threats.first { $0.source.id == "component:\(component)" })
        let control = try #require(threat.controls.first)

        _ = SetControlStatus(models: models).execute(
            SetControlStatusRequest(controlKey: control.key, statusId: "implemented")
        )
        #expect(models.undoLabel == ChangeLabel.setControlStatus)

        _ = OverrideThreatSeverity(models: models, catalogue: catalogue).execute(
            OverrideThreatSeverityRequest(overrideKey: threat.overrideKey, severityId: "low")
        )
        #expect(models.undoLabel == ChangeLabel.overrideSeverity)

        _ = ClearSeverityOverride(models: models).execute(
            ClearSeverityOverrideRequest(overrideKey: threat.overrideKey)
        )
        #expect(models.undoLabel == ChangeLabel.clearSeverityOverride)

        _ = SetCompensatingControl(models: models).execute(
            SetCompensatingControlRequest(
                threatKey: threat.threatKey,
                label: "Watched by the SIEM",
                reducesRiskBy: 50,
                rationale: "The account alerts on use."
            )
        )
        #expect(models.undoLabel == ChangeLabel.setCompensatingControl)
    }

    @Test func undoAndRedoNameTheChangeTheyMove() throws {
        _ = addAComponent()

        let undone = UndoLastChange(models: models).execute(UndoLastChangeRequest())
        #expect(undone == .undone(canUndoMore: false, label: ChangeLabel.addComponent))
        #expect(models.redoLabel == ChangeLabel.addComponent)

        let redone = RedoChange(models: models).execute(RedoChangeRequest())
        #expect(redone == .redone(canRedoMore: false, label: ChangeLabel.addComponent))
        #expect(models.undoLabel == ChangeLabel.addComponent)
    }

    @Test func namesNothingWhenTheHistoryIsEmpty() {
        #expect(models.undoLabel == nil)
        #expect(models.redoLabel == nil)
        #expect(UndoLastChange(models: models).execute(UndoLastChangeRequest()) == .nothingToUndo)
    }

    /// The labels this application holds, so a new use case that forgets to
    /// name its change shows up as a name nothing states.
    @Test func statesEveryLabel() {
        let labels = [
            ChangeLabel.addComponent, ChangeLabel.moveComponents, ChangeLabel.removeComponents,
            ChangeLabel.connectComponents, ChangeLabel.removeConnection,
            ChangeLabel.setConnectionProperties, ChangeLabel.reverseConnection,
            ChangeLabel.labelConnection, ChangeLabel.addZone, ChangeLabel.resizeZone,
            ChangeLabel.removeZone, ChangeLabel.setZoneProperties,
            ChangeLabel.setComponentProperties, ChangeLabel.paste, ChangeLabel.duplicate,
            ChangeLabel.recordControl, ChangeLabel.setControlStatus,
            ChangeLabel.overrideSeverity, ChangeLabel.clearSeverityOverride,
            ChangeLabel.setCompensatingControl, ChangeLabel.setLikelihoodFinding,
            ChangeLabel.configurePathwayMitigations, ChangeLabel.setMitigatesEdge,
            ChangeLabel.setAssumption, ChangeLabel.removeAssumption,
            ChangeLabel.createCustomTechnology, ChangeLabel.editCustomTechnology,
            ChangeLabel.deleteCustomTechnology, ChangeLabel.renameThreatModel,
            ChangeLabel.importArchitecture, ChangeLabel.applyAnswers,
            ChangeLabel.adoptCatalogue, ChangeLabel.save
        ]

        #expect(labels.allSatisfy { $0.isEmpty == false })
        #expect(labels.allSatisfy { $0 != ChangeLabel.unnamed })
        #expect(Set(labels).count == labels.count)
    }
}
