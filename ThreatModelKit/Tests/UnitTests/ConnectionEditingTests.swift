import Testing
import ThreatModelKit
import TestSupport

@Suite("Editing a flow")
struct ConnectionEditingTests {
    private let models = InMemoryThreatModelGateway()
    private let ids = SequentialIdentityGenerator()
    private let catalogue = CatalogueFixture.catalogue()

    private func twoComponents() -> (String, String) {
        let add = AddComponent(models: models, catalogue: catalogue, ids: ids)
        guard case .added(let first) = add.execute(
            AddComponentRequest(technologyId: "aws-ec2", x: 0, y: 0, sensitivity: "confidential")
        ), case .added(let second) = add.execute(
            AddComponentRequest(technologyId: "aws-rds", x: 400, y: 0, sensitivity: "restricted")
        ) else {
            Issue.record("expected two components")
            return ("", "")
        }
        return (first, second)
    }

    private func aFlow() -> (id: String, source: String, target: String) {
        let (first, second) = twoComponents()
        guard case .connected(let id) = ConnectComponents(models: models, ids: ids).execute(
            ConnectComponentsRequest(sourceComponentId: first, targetComponentId: second)
        ) else {
            Issue.record("expected a flow")
            return ("", first, second)
        }
        return (id, first, second)
    }

    // MARK: labelling

    @Test func writesTheLabelTheConnectionPanelReads() throws {
        let flow = aFlow()

        #expect(
            LabelConnection(models: models)
                .execute(LabelConnectionRequest(connectionId: flow.id, label: "  the card number  "))
                == .labelled
        )

        // One field, one value: the label is the description the panel edits.
        let written = try #require(models.current().connections.first)
        #expect(written.description == "the card number")
    }

    @Test func clearsTheLabelForAnEmptyText() throws {
        let flow = aFlow()
        _ = LabelConnection(models: models)
            .execute(LabelConnectionRequest(connectionId: flow.id, label: "the card number"))

        _ = LabelConnection(models: models)
            .execute(LabelConnectionRequest(connectionId: flow.id, label: "   "))

        #expect(try #require(models.current().connections.first).description == nil)
    }

    @Test func labellingIsOneUndoableChange() throws {
        let flow = aFlow()
        _ = LabelConnection(models: models)
            .execute(LabelConnectionRequest(connectionId: flow.id, label: "the card number"))
        #expect(models.undoLabel == ChangeLabel.labelConnection)

        _ = models.undo()

        #expect(try #require(models.current().connections.first).description == nil)
    }

    @Test func labelsNoFlowTheModelDoesNotHold() {
        #expect(
            LabelConnection(models: models)
                .execute(LabelConnectionRequest(connectionId: "no-such-flow", label: "x"))
                == .unknownConnection
        )
    }

    // MARK: reversing

    @Test func swapsTheEndsAndKeepsTheKindAndTheLabel() throws {
        let flow = aFlow()
        _ = SetConnectionProperties(models: models).execute(
            SetConnectionPropertiesRequest(
                connectionId: flow.id,
                kind: "ipc",
                description: "the card number"
            )
        )

        #expect(
            ReverseConnection(models: models)
                .execute(ReverseConnectionRequest(connectionId: flow.id)) == .reversed
        )

        let reversed = try #require(models.current().connections.first)
        #expect(reversed.source.value == flow.target)
        #expect(reversed.target.value == flow.source)
        #expect(reversed.kind == .ipc)
        #expect(reversed.description == "the card number")
        #expect(reversed.id.value == flow.id)
    }

    @Test func reversingIsOneUndoableChange() throws {
        let flow = aFlow()

        _ = ReverseConnection(models: models).execute(ReverseConnectionRequest(connectionId: flow.id))
        #expect(models.undoLabel == ChangeLabel.reverseConnection)

        _ = models.undo()

        let back = try #require(models.current().connections.first)
        #expect(back.source.value == flow.source)
        #expect(back.target.value == flow.target)
    }

    @Test func refusesToReverseOntoAFlowTheModelAlreadyHolds() throws {
        let flow = aFlow()
        _ = ConnectComponents(models: models, ids: ids).execute(
            ConnectComponentsRequest(
                sourceComponentId: flow.target,
                targetComponentId: flow.source
            )
        )

        #expect(
            ReverseConnection(models: models)
                .execute(ReverseConnectionRequest(connectionId: flow.id)) == .alreadyConnected
        )
        #expect(try #require(models.current().connections.first).source.value == flow.source)
    }

    @Test func reversesNoFlowTheModelDoesNotHold() {
        #expect(
            ReverseConnection(models: models)
                .execute(ReverseConnectionRequest(connectionId: "no-such-flow"))
                == .unknownConnection
        )
    }

    /// The `.arch` file writes `flow b -> a` where it wrote `flow a -> b`.
    @Test func writesTheReversedFlowToTheFile() throws {
        let app = TestDependencies()
        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(text: """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }

              component "db" {
                technology = "aws-rds"
                data       = "restricted"
              }

              flow api -> db
            }
            """)
        )

        _ = app.reverseConnection().execute(ReverseConnectionRequest(connectionId: "api->db"))

        let text = app.exportArchitecture().execute(ExportArchitectureRequest()).text

        #expect(text.contains("flow db -> api"))
        #expect(text.contains("flow api -> db") == false)
    }
}
