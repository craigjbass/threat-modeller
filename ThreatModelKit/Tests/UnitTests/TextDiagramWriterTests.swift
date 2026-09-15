@testable import DiagramRendering
import Foundation
import Testing
import ThreatModelKit
import TestSupport

@Suite("Writing the diagram as text")
struct TextDiagramWriterTests {
    /// One sample system: two zones, an actor outside them, a store inside
    /// one, and a flow of each kind the picture draws.
    private func model() -> DiagramBuilder.Model {
        DiagramBuilder.Model(
            components: [
                ViewedComponent(
                    id: "attacker",
                    technologyId: "actor-attacker",
                    name: "Attacker",
                    customName: nil,
                    providerId: "actor",
                    categoryId: "actor",
                    x: 0,
                    y: 0,
                    sensitivityId: "public",
                    threatsDisabled: false,
                    isUnknownTechnology: false,
                    zoneId: nil,
                    shapeId: "actor"
                ),
                ViewedComponent(
                    id: "api",
                    technologyId: "aws-ec2",
                    name: "API",
                    customName: "API",
                    providerId: "aws",
                    categoryId: "compute",
                    x: 100,
                    y: 0,
                    sensitivityId: "confidential",
                    threatsDisabled: false,
                    isUnknownTechnology: false,
                    zoneId: "app",
                    shapeId: "process"
                ),
                ViewedComponent(
                    id: "db",
                    technologyId: "aws-rds",
                    name: "Ledger \"main\"",
                    customName: "Ledger \"main\"",
                    providerId: "aws",
                    categoryId: "database",
                    x: 200,
                    y: 0,
                    sensitivityId: "restricted",
                    threatsDisabled: false,
                    isUnknownTechnology: false,
                    zoneId: "data",
                    shapeId: "store"
                )
            ],
            connections: [
                ViewedConnection(
                    id: "attacker->api",
                    sourceComponentId: "attacker",
                    targetComponentId: "api",
                    kindId: "network"
                ),
                ViewedConnection(
                    id: "api->db",
                    sourceComponentId: "api",
                    targetComponentId: "db",
                    kindId: "ipc"
                )
            ],
            zones: [
                ViewedZone(
                    id: "app",
                    name: "App zone",
                    customName: "App zone",
                    networkZoneId: "private",
                    networkTypeId: "generic",
                    riskReductionEnabled: true,
                    riskReductionPercent: 20,
                    x: 0,
                    y: 0,
                    width: 100,
                    height: 100,
                    boundaryId: "network"
                ),
                ViewedZone(
                    id: "data",
                    name: "Data zone",
                    customName: "Data zone",
                    networkZoneId: "private",
                    networkTypeId: "generic",
                    riskReductionEnabled: true,
                    riskReductionPercent: 20,
                    x: 200,
                    y: 0,
                    width: 100,
                    height: 100,
                    boundaryId: "network"
                )
            ]
        )
    }

    // MARK: Mermaid

    @Test func mermaidWritesTheZonesAsSubgraphs() {
        let text = TextDiagramWriter.mermaid(of: model())

        #expect(text.hasPrefix("flowchart LR\n"))
        #expect(text.contains("  subgraph app[\"App zone\"]"))
        #expect(text.contains("  subgraph data[\"Data zone\"]"))
        #expect(text.contains("  end"))
    }

    @Test func mermaidWritesEachComponentInItsOwnShape() {
        let text = TextDiagramWriter.mermaid(of: model())

        #expect(text.contains("attacker([\"Attacker\"])"))
        #expect(text.contains("api[\"API\"]"))
        #expect(text.contains("db[(\"Ledger #quot;main#quot;\")]"))
    }

    @Test func mermaidStatesTheKindOnEachFlow() {
        let text = TextDiagramWriter.mermaid(of: model())

        #expect(text.contains("attacker -->|\"Network\"| api"))
        #expect(text.contains("api -->|\"Local IPC\"| db"))
    }

    // MARK: Graphviz DOT

    @Test func dotWritesTheZonesAsClusters() {
        let text = TextDiagramWriter.dot(of: model())

        #expect(text.hasPrefix("digraph {\n"))
        #expect(text.contains("  subgraph cluster_app {"))
        #expect(text.contains("    label=\"App zone\";"))
        #expect(text.hasSuffix("}\n"))
    }

    @Test func dotWritesEachComponentInItsOwnShape() {
        let text = TextDiagramWriter.dot(of: model())

        #expect(text.contains("attacker [label=\"Attacker\", shape=ellipse];"))
        #expect(text.contains("api [label=\"API\", shape=box];"))
        #expect(text.contains("db [label=\"Ledger \\\"main\\\"\", shape=cylinder];"))
    }

    @Test func dotStatesTheKindOnEachFlow() {
        let text = TextDiagramWriter.dot(of: model())

        #expect(text.contains("attacker -> api [label=\"Network\"];"))
        #expect(text.contains("api -> db [label=\"Local IPC\"];"))
    }

    // MARK: D2

    @Test func d2WritesTheZonesAsContainers() {
        let text = TextDiagramWriter.d2(of: model())

        #expect(text.contains("app: \"App zone\" {"))
        #expect(text.contains("data: \"Data zone\" {"))
    }

    @Test func d2WritesEachComponentInItsOwnShape() {
        let text = TextDiagramWriter.d2(of: model())

        #expect(text.contains("attacker: \"Attacker\" { shape: person }"))
        #expect(text.contains("api: \"API\" { shape: rectangle }"))
        #expect(text.contains("db: \"Ledger \\\"main\\\"\" { shape: cylinder }"))
    }

    /// A component inside a zone is addressed through the zone, the way D2
    /// addresses anything nested.
    @Test func d2AddressesAComponentThroughItsZone() {
        let text = TextDiagramWriter.d2(of: model())

        #expect(text.contains("attacker -> app.api: \"Network\""))
        #expect(text.contains("app.api -> data.db: \"Local IPC\""))
    }

    // MARK: what each language quotes

    /// A name holding a character the target language reads as syntax is
    /// escaped. These are the characters checked: a quotation mark, a hash, a
    /// backslash, an angle bracket and a newline.
    @Test func aNameHoldingSyntaxIsEscaped() {
        let awkward = "a \"quote\" #hash \\slash <angle>\nsecond line"

        let mermaid = TextDiagramWriter.mermaidText(awkward)
        #expect(mermaid.contains("#quot;"))
        #expect(mermaid.contains("#35;"))
        #expect(mermaid.contains("#lt;"))
        #expect(mermaid.contains("#gt;"))
        #expect(mermaid.contains("\n") == false)
        #expect(mermaid.hasPrefix("\"") && mermaid.hasSuffix("\""))

        let dot = TextDiagramWriter.dotText(awkward)
        #expect(dot.contains("\\\""))
        #expect(dot.contains("\\\\"))
        #expect(dot.contains("\n") == false)

        let d2 = TextDiagramWriter.d2Text(awkward)
        #expect(d2.contains("\\\""))
        #expect(d2.contains("\\\\"))
        #expect(d2.contains("\n") == false)
    }

    /// An identifier every one of the three languages accepts.
    @Test func anIdentifierHoldsOnlyLettersDigitsAndUnderscores() {
        #expect(TextDiagramWriter.identifier("api-gateway") == "api_gateway")
        #expect(TextDiagramWriter.identifier("cdn->api") == "cdn__api")
        #expect(TextDiagramWriter.identifier("2fa") == "n2fa")
        #expect(TextDiagramWriter.identifier("!!") == "__")
    }

    /// Two runs on one model give the same bytes, so a file in a repository
    /// changes only when the model changes.
    @Test func twoRunsOfOneModelGiveTheSameBytes() {
        for language in TextDiagramWriter.Language.allCases {
            let first = TextDiagramWriter.text(of: model(), in: language)
            let second = TextDiagramWriter.text(of: model(), in: language)
            #expect(first == second, "\(language.rawValue) is not the same twice")
        }
    }

    // MARK: the golden files

    @Test func eachLanguageMatchesItsGoldenFile() throws {
        for language in TextDiagramWriter.Language.allCases {
            let written = TextDiagramWriter.text(of: model(), in: language)
            let golden = try Self.golden("payments-diagram.\(language.fileExtension)")
            #expect(written == golden, "\(language.rawValue) changed")
        }
    }

    @Test func writesTheGoldenFilesWhenAskedTo() throws {
        guard ProcessInfo.processInfo.environment["THREATMODELLER_WRITE_GOLDENS"] == "1" else {
            return
        }
        for language in TextDiagramWriter.Language.allCases {
            try TextDiagramWriter.text(of: model(), in: language)
                .write(
                    to: Self.goldensDirectory
                        .appendingPathComponent("payments-diagram.\(language.fileExtension)"),
                    atomically: true,
                    encoding: .utf8
                )
        }
    }

    private static var goldensDirectory: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Goldens")
    }

    private static func golden(_ name: String) throws -> String {
        try String(contentsOf: goldensDirectory.appendingPathComponent(name), encoding: .utf8)
    }
}
