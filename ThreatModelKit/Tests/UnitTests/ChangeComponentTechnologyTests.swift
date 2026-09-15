import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// Putting a different technology on a component that is already drawn.
@Suite("Changing a component's technology")
struct ChangeComponentTechnologyTests {
    private let app = TestDependencies()

    /// Two components, a flow between them, and the answers a person gives.
    private func drawn() -> (String, String) {
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  component "api" {
                    technology = "aws-ec2"
                    data       = "confidential"
                  }

                  component "db" { technology = "aws-rds" }

                  flow api -> db
                }
                """
            )
        )
        let model = app.modelStore.current()
        return (model.components[0].id.value, model.components[1].id.value)
    }

    private func change(_ componentId: String, to technologyId: String) -> ChangeComponentTechnologyResponse {
        app.changeComponentTechnology().execute(
            ChangeComponentTechnologyRequest(componentId: componentId, technologyId: technologyId)
        )
    }

    private func threats(on componentId: String) -> [AssessedThreat] {
        app.assessThreatModel().execute(AssessThreatModelRequest()).threats.filter {
            if case .component(let id, _, _) = $0.source { return id == componentId }
            return false
        }
    }

    @Test func keepsTheIdTheNameThePlaceTheZoneAndTheFlows() throws {
        let (api, _) = drawn()
        _ = app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: api,
                name: "Payments API",
                sensitivity: "restricted",
                threatsDisabled: false,
                runsAs: "root"
            )
        )
        let before = try #require(app.modelStore.current().component(ComponentId(api)))

        #expect(change(api, to: "aws-rds") != .unknownTechnology)

        let after = try #require(app.modelStore.current().component(ComponentId(api)))
        #expect(after.id == before.id)
        #expect(after.customName == "Payments API")
        #expect(after.position == before.position)
        #expect(after.sensitivity == before.sensitivity)
        #expect(after.runsAs == before.runsAs)
        #expect(after.technologyId == TechnologyId("aws-rds"))
        #expect(app.modelStore.current().connections.count == 1)
    }

    @Test func refusesATechnologyNothingHolds() {
        let (api, _) = drawn()

        #expect(change(api, to: "not-a-technology") == .unknownTechnology)
    }

    @Test func refusesAComponentTheModelDoesNotHold() {
        _ = drawn()

        #expect(change("ghost", to: "aws-rds") == .unknownComponent)
    }

    @Test func changesNothingWhenTheTechnologyIsAlreadyThatOne() {
        let (api, _) = drawn()

        #expect(change(api, to: "aws-ec2") == .unchanged)
    }

    /// An answer belongs to a threat. A threat the new technology still raises
    /// keeps its answer, and a threat it does not raise loses it.
    @Test func keepsAnAnswerTheNewTechnologyStillRaisesAndDropsTheRest() throws {
        let (api, _) = drawn()
        let before = threats(on: api)
        for threat in before {
            for control in threat.controls {
                _ = app.setControlStatus().execute(
                    SetControlStatusRequest(controlKey: control.key, statusId: "implemented")
                )
            }
        }
        let answeredThreatIds = Set(before.map { $0.threatId })

        guard case .changed(let dropped) = change(api, to: "aws-rds") else {
            Issue.record("expected the technology to change")
            return
        }

        let raisedNow = Set(threats(on: api).map { $0.threatId })
        #expect(Set(dropped) == answeredThreatIds.subtracting(raisedNow))

        // Every answer left belongs to a threat the component still raises.
        for key in app.modelStore.current().controlStatuses.keys
        where key.value.hasPrefix("node:\(api):") {
            let read = try #require(ControlIdentity.read(key))
            #expect(raisedNow.contains(read.threatId.value))
        }
    }

    @Test func leavesTheAnswersOnEveryOtherComponentAlone() throws {
        let (api, db) = drawn()
        let onTheOther = try #require(threats(on: db).first?.controls.first)
        _ = app.setControlStatus().execute(
            SetControlStatusRequest(controlKey: onTheOther.key, statusId: "implemented")
        )

        _ = change(api, to: "aws-rds")

        #expect(app.modelStore.current().controlStatuses[ControlKey(onTheOther.key)] != nil)
    }

    @Test func costsOneUndo() throws {
        let (api, _) = drawn()

        _ = change(api, to: "aws-rds")
        _ = app.undoLastChange().execute(UndoLastChangeRequest())

        let back = try #require(app.modelStore.current().component(ComponentId(api)))
        #expect(back.technologyId == TechnologyId("aws-ec2"))
    }

    /// The file a change writes is the file a person would have written with
    /// the new technology from the start.
    @Test func writesTheSameFileAsOneDrawnWithThatTechnologyFromTheStart() throws {
        let (api, _) = drawn()
        _ = change(api, to: "aws-rds")

        let changed = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        let fresh = TestDependencies()
        _ = fresh.importArchitecture().execute(
            ImportArchitectureRequest(
                text: """
                system "Payments" {
                  component "api" {
                    technology = "aws-rds"
                    data       = "confidential"
                  }

                  component "db" { technology = "aws-rds" }

                  flow api -> db
                }
                """
            )
        )
        let written = fresh.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(changed == written)
    }
}
