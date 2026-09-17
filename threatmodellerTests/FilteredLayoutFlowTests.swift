import CoreGraphics
import Foundation
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// A narrowed diagram is laid out on its own, in view state.
///
/// Issue #156 and
/// `docs/superpowers/specs/2026-09-17-filtered-layout-design.md`: the tag
/// filter and Focus lay the drawn set out with the search the full diagram
/// uses, the canvas fits the result, and the model and the `.arch` file stay
/// as they are.
@MainActor
@Suite("A filtered diagram lays the drawn set out")
struct FilteredLayoutFlowTests {
    private let payments = """
    system "Payments" {
      zone "app" {
        kind = "private"

        component "api" {
          technology = "aws-ec2"
          tags       = ["payments"]
        }

        component "db" {
          technology = "aws-rds"
        }
      }

      zone "edge" {
        kind = "public"

        component "cdn" {
          technology = "aws-cloudfront"
          tags       = ["edge"]
        }

        component "lb" {
          technology = "aws-elb"
        }
      }

      flow cdn -> lb
      flow lb -> api
      flow api -> db
    }

    """

    // MARK: what a test draws

    private func aModel() -> ThreatModelSession {
        let useCases = TestDependencies()
        _ = useCases.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        return ThreatModelSession(useCases: useCases)
    }

    private func aCanvas(for session: ThreatModelSession) -> CanvasState {
        let canvas = CanvasState()
        canvas.layouts = session
        canvas.visibleSize = CGSize(width: 900, height: 700)
        return canvas
    }

    private func modelPositions(_ session: ThreatModelSession) -> [String: CGPoint] {
        Dictionary(
            uniqueKeysWithValues: session.canvas.components.map {
                ($0.id, CGPoint(x: $0.x, y: $0.y))
            }
        )
    }

    private func drawnPositions(
        _ canvas: CanvasState,
        in session: ThreatModelSession
    ) -> [String: CGPoint] {
        Dictionary(
            uniqueKeysWithValues: canvas.drawn(in: session.canvas).components.map {
                ($0.id, CGPoint(x: $0.x, y: $0.y))
            }
        )
    }

    /// How much room a set of elements covers, so a narrowed picture is
    /// compared with the same elements in the full layout.
    private func area(components: [(x: Double, y: Double)], zones: [(x: Double, y: Double, width: Double, height: Double)]) -> Double {
        guard let rect = SelectionBounds.rect(
            components: components.map {
                ($0.x, $0.y, Component.size.width, Component.size.height)
            },
            zones: zones
        ) else { return 0 }
        return rect.width * rect.height
    }

    // MARK: the narrowed layout

    /// The drawn set is a picture in its own right: it covers less room than
    /// the same elements cover in the full layout, and the model does not
    /// move.
    @Test func theNarrowedSetIsLaidOutOnItsOwnAndNotLeftWhereTheFullLayoutPutIt() throws {
        let session = aModel()
        let canvas = aCanvas(for: session)
        let before = modelPositions(session)

        canvas.pick(tag: "payments")
        canvas.pick(tag: "edge")

        let drawn = canvas.drawn(in: session.canvas)
        #expect(drawn.components.map(\.id).sorted() == ["api", "cdn"])
        #expect(drawn.zones.map(\.id).sorted() == ["app", "edge"])

        let drawnIds = Set(drawn.components.map(\.id))
        let drawnZoneIds = Set(drawn.zones.map(\.id))
        let narrowed = area(
            components: drawn.components.map { ($0.x, $0.y) },
            zones: drawn.zones.map { ($0.x, $0.y, $0.width, $0.height) }
        )
        let full = area(
            components: session.canvas.components
                .filter { drawnIds.contains($0.id) }
                .map { ($0.x, $0.y) },
            zones: session.canvas.zones
                .filter { drawnZoneIds.contains($0.id) }
                .map { ($0.x, $0.y, $0.width, $0.height) }
        )
        #expect(narrowed < full)
        #expect(modelPositions(session) == before)
    }

    /// The tag filter lays its own set out, and the canvas fits the result
    /// rather than the whole diagram.
    @Test func thePickedTagLaysItsSetOutAndTheCanvasFitsTheResult() throws {
        let session = aModel()
        let canvas = aCanvas(for: session)

        canvas.pick(tag: "payments")

        let drawn = canvas.drawn(in: session.canvas)
        let fitted = try #require(
            SelectionBounds.rect(
                components: drawn.components.map {
                    ($0.x, $0.y, Component.size.width, Component.size.height)
                },
                zones: drawn.zones.map { ($0.x, $0.y, $0.width, $0.height) }
            )
        )
        #expect(canvas.transform == CanvasTransform().fitting(fitted, in: canvas.visibleSize))
    }

    /// A deeper neighbour count lays the wider set out. The zone that gains a
    /// component is drawn bigger than it was drawn holding one.
    @Test func aDeeperNeighbourCountLaysTheWiderSetOut() throws {
        let session = aModel()
        let canvas = aCanvas(for: session)
        let before = modelPositions(session)
        canvas.focus(componentId: "api")
        let alone = try #require(canvas.narrowedZoneRects["app"])

        canvas.setNeighbourDepth(1)

        #expect(drawnPositions(canvas, in: session).keys.sorted() == ["api", "db", "lb"])
        let wider = try #require(canvas.narrowedZoneRects["app"])
        #expect(wider.width * wider.height > alone.width * alone.height)
        #expect(modelPositions(session) == before)
    }

    /// Two tags picked in either order draw the same picture, because every
    /// run reads the model's own coordinates and never the run before.
    @Test func pickingTwoTagsInEitherOrderDrawsTheSamePositions() {
        let session = aModel()

        let one = aCanvas(for: session)
        one.pick(tag: "payments")
        one.pick(tag: "edge")

        let other = aCanvas(for: session)
        other.pick(tag: "edge")
        other.pick(tag: "payments")

        #expect(one.drawn(in: session.canvas) == other.drawn(in: session.canvas))
        #expect(one.transform == other.transform)
    }

    /// Clearing the filter draws the model's own coordinates again, and fits
    /// the whole diagram the way Zoom to Fit does.
    @Test func clearingTheFilterDrawsTheModelAgainAndFitsTheWholeDiagram() {
        let session = aModel()
        let canvas = aCanvas(for: session)
        let before = modelPositions(session)
        canvas.focus(componentId: "api")

        canvas.clearTagFilter()

        #expect(drawnPositions(canvas, in: session) == before)
        #expect(canvas.narrowedComponentPositions.isEmpty)
        #expect(canvas.narrowedZoneRects.isEmpty)
        #expect(modelPositions(session) == before)

        let zoomedToFit = CanvasState()
        zoomedToFit.visibleSize = canvas.visibleSize
        CanvasGestures(session: session, canvas: zoomedToFit).zoomToFit()
        #expect(canvas.transform == zoomedToFit.transform)
    }

    /// The canvas draws every element of the narrowed set at every step, so
    /// a second pick never leaves a blank.
    @Test func narrowingAgainNeverDrawsABlank() {
        let session = aModel()
        let canvas = aCanvas(for: session)

        canvas.pick(tag: "payments")
        #expect(canvas.drawn(in: session.canvas).components.isEmpty == false)

        canvas.pick(tag: "edge")
        #expect(canvas.drawn(in: session.canvas).components.count == 2)

        canvas.setNeighbourDepth(2)
        #expect(canvas.drawn(in: session.canvas).components.count == 4)
    }

    // MARK: a drag while a filter is on

    /// The drag moves the picture. The model keeps its own coordinates.
    @Test func aDragWhileAFilterIsOnMovesThePictureAndNotTheModel() throws {
        let session = aModel()
        let canvas = aCanvas(for: session)
        canvas.pick(tag: "payments")
        canvas.transform = CanvasTransform()
        let before = modelPositions(session)
        let drawnBefore = try #require(drawnPositions(canvas, in: session)["api"])
        canvas.select(componentId: "api", addingToSelection: false)

        CanvasGestures(session: session, canvas: canvas)
            .nodeDragEnded(CGSize(width: 40, height: 25))

        let drawnAfter = try #require(drawnPositions(canvas, in: session)["api"])
        #expect(drawnAfter.x == drawnBefore.x + 40)
        #expect(drawnAfter.y == drawnBefore.y + 25)
        #expect(modelPositions(session) == before)
    }

    /// The move is dropped at the next filter change: the run starts from the
    /// model's own coordinates.
    @Test func theNextFilterChangeDropsTheDraggedPosition() throws {
        let session = aModel()
        let canvas = aCanvas(for: session)
        canvas.pick(tag: "payments")
        canvas.transform = CanvasTransform()
        let drawnBefore = try #require(drawnPositions(canvas, in: session)["api"])
        canvas.select(componentId: "api", addingToSelection: false)
        CanvasGestures(session: session, canvas: canvas)
            .nodeDragEnded(CGSize(width: 40, height: 25))

        canvas.setNeighbourDepth(0)

        #expect(drawnPositions(canvas, in: session)["api"] == drawnBefore)
    }

    /// A drag with no filter on still moves the model, the way it always did.
    @Test func aDragWithNoFilterOnStillMovesTheModel() throws {
        let session = aModel()
        let canvas = aCanvas(for: session)
        let before = try #require(modelPositions(session)["api"])
        canvas.select(componentId: "api", addingToSelection: false)

        CanvasGestures(session: session, canvas: canvas)
            .nodeDragEnded(CGSize(width: 40, height: 25))

        #expect(modelPositions(session)["api"]?.x == before.x + 40)
        #expect(canvas.narrowedComponentPositions.isEmpty)
    }

    // MARK: the file

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    /// The acceptance criterion: a save while a Focus is on writes the full
    /// layout the file already holds.
    @Test func aSaveWhileAFocusIsOnLeavesTheArchitectureFileAlone() async throws {
        let (project, useCases) = await aProject()
        let session = try #require(project.model)
        let canvas = aCanvas(for: session)
        // Written once first, so the text compared is what this application
        // writes rather than what the test typed.
        await project.save()
        let fileBefore = try #require(useCases.project.text(at: "/work/threatmodel/payments.arch"))
        let modelBefore = modelPositions(session)

        canvas.focus(componentId: "cdn")

        #expect(drawnPositions(canvas, in: session)["cdn"] != modelBefore["cdn"])
        #expect(modelPositions(session) == modelBefore)

        await project.save()

        #expect(useCases.project.text(at: "/work/threatmodel/payments.arch") == fileBefore)
        #expect(modelPositions(session) == modelBefore)
    }
}
