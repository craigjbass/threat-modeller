import Testing
import ThreatModelKit
import TestSupport

/// Given a project directory a team commits
/// When I open a system, change it and save
/// Then the text on disk is the change, and opening it again shows it
struct KeepingAProjectInGitTests {
    private let app = TestDependencies()

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject() {
        app.project.put(payments, at: "/work/threatmodel/payments.arch")
    }

    @Test func carriesAChangeThroughTheTextOnDisk() throws {
        aProject()
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        guard case .added(let componentId) = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 900, y: 40, sensitivity: "restricted")
        ) else {
            Issue.record("the component was not added")
            return
        }
        _ = app.setComponentProperties().execute(
            SetComponentPropertiesRequest(
                componentId: componentId,
                name: "Customer Database",
                sensitivity: "restricted",
                threatsDisabled: false
            )
        )
        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))

        // A second application, reading only what is on disk.
        let reader = TestDependencies()
        reader.project.put(
            try #require(app.project.text(at: "/work/threatmodel/payments.arch")),
            at: "/work/threatmodel/payments.arch"
        )
        _ = reader.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))

        let view = reader.viewThreatModel().execute(ViewThreatModelRequest())
        #expect(view.components.count == 2)
        #expect(view.components.contains { $0.name == "Customer Database" })
        #expect(reader.assessThreatModel().execute(AssessThreatModelRequest()).threats.isEmpty == false)
    }

    @Test func writesNoCoordinates() throws {
        aProject()
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        _ = app.moveComponents().execute(
            MoveComponentsRequest(moves: [ComponentMove(componentId: "api", x: 900, y: 700)])
        )
        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))

        let written = try #require(app.project.text(at: "/work/threatmodel/payments.arch"))

        // A layout a user adjusts by hand is not written back. The picture is
        // drawn from declaration order every time.
        #expect(written == payments)
    }
}
