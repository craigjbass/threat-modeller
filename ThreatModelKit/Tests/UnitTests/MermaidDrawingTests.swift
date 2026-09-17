import DiagramRendering
import Testing
import ThreatModelKit

/// Reading a mermaid flowchart, so the window draws a diagram block rather
/// than showing its source.
///
/// The design is
/// `docs/superpowers/specs/2026-09-17-report-stage-pictures-design.md`.
@Suite("Reading a mermaid flowchart")
struct MermaidDrawingTests {
    private func labels(of drawing: DiagramDrawing) -> [String] {
        drawing.shapes.compactMap { shape in
            if case .text(let text, _, _, _, _, _) = shape { return text }
            return nil
        }
    }

    // MARK: what the reader reads

    @Test func readsTheNodesAndTheEdgesOfAFlowchart() throws {
        let graph = try #require(
            MermaidDrawing.graph(
                of: """
                flowchart TD
                  api[API] --> store[(Database)]
                  api --> queue{{Queue}}
                """
            )
        )

        #expect(graph.direction == .down)
        #expect(graph.nodes.map(\.id) == ["api", "store", "queue"])
        #expect(graph.nodes.map(\.label) == ["API", "Database", "Queue"])
        #expect(graph.edges.map(\.from) == ["api", "api"])
        #expect(graph.edges.map(\.to) == ["store", "queue"])
        #expect(graph.edges.map(\.hasArrow) == [true, true])
    }

    /// A chain writes one edge per arrow, the way mermaid reads one.
    @Test func readsAChainAsOneEdgePerArrow() throws {
        let graph = try #require(MermaidDrawing.graph(of: "graph LR; a --> b --> c;"))

        #expect(graph.direction == .right)
        #expect(graph.nodes.map(\.id) == ["a", "b", "c"])
        #expect(graph.edges.map(\.to) == ["b", "c"])
    }

    @Test func readsTheLabelOnAnEdge() throws {
        let graph = try #require(
            MermaidDrawing.graph(
                of: """
                flowchart LR
                  user -->|reads| api
                  api -- writes --> store
                """
            )
        )

        #expect(graph.edges.map(\.label) == ["reads", "writes"])
    }

    /// A line with no arrow is an edge with no arrow head, and a dotted line
    /// is a dashed one.
    @Test func readsTheShapeOfALine() throws {
        let graph = try #require(
            MermaidDrawing.graph(
                of: """
                flowchart TD
                  a --- b
                  b -.-> c
                """
            )
        )

        #expect(graph.edges.map(\.hasArrow) == [false, true])
        #expect(graph.edges.map(\.isDashed) == [false, true])
    }

    @Test func readsASubgraphAsAGroup() throws {
        let graph = try #require(
            MermaidDrawing.graph(
                of: """
                flowchart TD
                  subgraph vpc [Private network]
                    api[API]
                    store[Store]
                  end
                  user --> api
                """
            )
        )

        #expect(graph.groups.map(\.title) == ["Private network"])
        #expect(graph.groups.first?.nodeIds == ["api", "store"])
        #expect(graph.nodes.map(\.id) == ["api", "store", "user"])
    }

    /// A comment, a style and a click say nothing about the picture.
    @Test func readsNothingFromACommentOrAStyle() throws {
        let graph = try #require(
            MermaidDrawing.graph(
                of: """
                flowchart TD
                  %% the login path
                  classDef hot fill:#f00
                  a --> b
                  style a fill:#eee
                  click a "https://example.com"
                  linkStyle 0 stroke:#333
                """
            )
        )

        #expect(graph.nodes.map(\.id) == ["a", "b"])
        #expect(graph.edges.count == 1)
    }

    // MARK: what the reader refuses

    /// A mermaid diagram of another kind draws nothing. The stage shows its
    /// text instead, the way it shows D2.
    @Test func readsNoDiagramOfAnotherKind() {
        #expect(MermaidDrawing.graph(of: "sequenceDiagram\n  a->>b: hello") == nil)
        #expect(MermaidDrawing.graph(of: "erDiagram\n  A ||--o{ B : has") == nil)
        #expect(MermaidDrawing.graph(of: "gantt\n  title A") == nil)
        #expect(MermaidDrawing.graph(of: "pie\n  \"a\" : 1") == nil)
    }

    @Test func readsNoGraphWithNoNodeInIt() {
        #expect(MermaidDrawing.graph(of: "flowchart TD") == nil)
        #expect(MermaidDrawing.graph(of: "") == nil)
    }

    // MARK: the picture

    /// The drawing carries every label, so a reader reads the same words the
    /// source states.
    @Test func drawsEveryLabelTheTextNames() throws {
        let drawing = try #require(
            MermaidDrawing.drawing(
                of: """
                flowchart TD
                  subgraph vpc [Private network]
                    api[API]
                  end
                  user[Person] -->|reads| api
                """
            )
        )

        let said = labels(of: drawing)
        #expect(said.contains("API"))
        #expect(said.contains("Person"))
        #expect(said.contains("reads"))
        #expect(said.contains("Private network"))
        #expect(drawing.size.width > 0)
        #expect(drawing.size.height > 0)
    }

    /// A rank runs down the page for `TD` and across it for `LR`, so the two
    /// pictures are not the same shape.
    @Test func laysTheRanksOutTheWayTheHeaderStates() throws {
        let down = try #require(MermaidDrawing.drawing(of: "flowchart TD\n a --> b --> c"))
        let across = try #require(MermaidDrawing.drawing(of: "flowchart LR\n a --> b --> c"))

        #expect(down.size.height > down.size.width)
        #expect(across.size.width > across.size.height)
    }

    /// A graph that loops still draws: the walk stops rather than running
    /// round the loop.
    @Test func drawsAGraphThatLoops() throws {
        let drawing = try #require(MermaidDrawing.drawing(of: "flowchart TD\n a --> b\n b --> a"))

        #expect(labels(of: drawing).contains("a"))
        #expect(labels(of: drawing).contains("b"))
    }

    /// A node with no bracket is named by its own identifier.
    @Test func namesANodeWithNoBracketByItsIdentifier() throws {
        let graph = try #require(MermaidDrawing.graph(of: "flowchart TD\n alpha --> beta"))

        #expect(graph.nodes.map(\.label) == ["alpha", "beta"])
    }

    /// SVG is the form the stage draws, so the drawing goes through the
    /// writer the exporters use.
    @Test func writesTheDrawingAsSvg() throws {
        let drawing = try #require(MermaidDrawing.drawing(of: "flowchart TD\n a[API] --> b[Store]"))
        let svg = SvgWriter.svg(of: drawing)

        #expect(svg.hasPrefix("<svg"))
        #expect(svg.contains("API"))
        #expect(svg.contains("Store"))
    }
}
