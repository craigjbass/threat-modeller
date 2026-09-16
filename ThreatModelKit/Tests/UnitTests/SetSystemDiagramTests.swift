import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// Writing a system's own diagram block into the architecture.
@Suite("Writing a system's own diagram")
struct SetSystemDiagramTests {
    private func app() -> TestDependencies {
        TestDependencies()
    }

    @discardableResult
    private func writeLogin(
        _ app: TestDependencies,
        text: String = "sequenceDiagram\n  Customer->>API: signs in"
    ) -> SetSystemDiagramResponse {
        app.setSystemDiagram().execute(
            SetSystemDiagramRequest(label: "The login sequence", text: text)
        )
    }

    // MARK: writing a block

    @Test func writesADiagram() throws {
        let app = app()

        #expect(writeLogin(app) == .recorded)

        let diagram = try #require(app.modelStore.current().diagrams.first)
        #expect(diagram.label == "The login sequence")
        #expect(diagram.kind == "mermaid")
        #expect(diagram.text == "sequenceDiagram\n  Customer->>API: signs in")
    }

    @Test func writesTheSameLabelAgainToChangeTheBlock() throws {
        let app = app()
        writeLogin(app)

        #expect(writeLogin(app, text: "sequenceDiagram\n  Customer->>API: signs out") == .recorded)

        let diagrams = app.modelStore.current().diagrams
        #expect(diagrams.count == 1)
        #expect(diagrams[0].text == "sequenceDiagram\n  Customer->>API: signs out")
    }

    @Test func refusesADiagramWithNoLabel() {
        let app = app()

        let response = app.setSystemDiagram().execute(
            SetSystemDiagramRequest(label: "  ", text: "sequenceDiagram")
        )

        #expect(response == .noLabel)
        #expect(app.modelStore.current().diagrams.isEmpty)
    }

    @Test func refusesADiagramWithNoText() {
        let app = app()

        let response = app.setSystemDiagram().execute(
            SetSystemDiagramRequest(label: "The login sequence", text: "  ")
        )

        #expect(response == .noText)
        #expect(app.modelStore.current().diagrams.isEmpty)
    }

    // MARK: taking a block off

    @Test func takesADiagramOff() {
        let app = app()
        writeLogin(app)

        let response = app.removeSystemDiagram().execute(
            RemoveSystemDiagramRequest(label: "The login sequence")
        )

        #expect(response == .removed)
        #expect(app.modelStore.current().diagrams.isEmpty)
    }

    @Test func saysSoWhenNoSuchDiagramIsThere() {
        let app = app()

        let response = app.removeSystemDiagram().execute(
            RemoveSystemDiagramRequest(label: "The login sequence")
        )

        #expect(response == .noSuchDiagram)
    }

    // MARK: what the window reads

    @Test func theViewListsTheDiagrams() throws {
        let app = app()
        writeLogin(app)

        let view = app.viewThreatModel().execute(ViewThreatModelRequest())

        let diagram = try #require(view.diagrams.first)
        #expect(diagram.label == "The login sequence")
        #expect(diagram.text == "sequenceDiagram\n  Customer->>API: signs in")
    }

    // MARK: the round trip

    @Test func aBlockWrittenInTheWindowRoundTripsThroughTheParser() throws {
        let app = app()
        writeLogin(app)

        let architecture = HclArchitectureSource()
        let built = ArchitectureSourceBuilder.source(from: app.modelStore.current())
        let written = architecture.write(built)
        let source = try #require(architecture.read(written).source)

        #expect(source.diagrams.count == 1)
        #expect(source.diagrams[0].label == "The login sequence")
        #expect(source.diagrams[0].kind == "mermaid")
        #expect(source.diagrams[0].text.contains("sequenceDiagram"))
    }
}
