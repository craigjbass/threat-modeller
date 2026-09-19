import AppKit
import CoreGraphics
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// What a person watches while the layout search runs.
///
/// The preview is the real diagram: the names, the icons, the zones and the
/// flows, at the coordinates the latest report gives, fitted to the column.
/// `docs/superpowers/specs/2026-09-17-layout-preview-design.md` states the
/// sampling rule and the measurement behind its number.
@MainActor
struct LayoutPreviewTests {
    private let payments = """
    system "Payments" {
      zone "app" {
        kind    = "private"
        network = "vpc"

        component "api" {
          technology = "aws-ec2"
          name       = "Orders API"
        }

        component "db" {
          technology = "aws-rds"
          name       = "Orders store"
        }
      }

      flow api -> db
    }

    """

    private func aProject() -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        return (
            ProjectSession(
                useCases: useCases,
                watcher: FakeProjectWatcher(),
                defaults: aTestDefaults()
            ),
            useCases
        )
    }

    private func aSubject(from useCases: TestDependencies) -> LayoutSubject {
        let drawn = useCases.viewThreatModel().execute(ViewThreatModelRequest())
        return LayoutSubject(
            components: drawn.components,
            connections: drawn.connections,
            zones: drawn.zones
        )
    }

    private func aLayout(over subject: LayoutSubject, shiftedBy shift: Double = 0) -> LayOutModelResponse {
        LayOutModelResponse(
            components: subject.components.map {
                LaidOutComponent(id: $0.id, x: $0.x + shift, y: $0.y)
            },
            zones: subject.zones.map {
                LaidOutZone(id: $0.id, x: $0.x + shift, y: $0.y, width: $0.width, height: $0.height)
            }
        )
    }

    // MARK: reading a picture

    /// True when the picture holds more than one colour, which tells a drawn
    /// diagram from a blank rectangle.
    private func hasContent(_ image: NSBitmapImageRep) -> Bool {
        var first: NSColor?
        for x in stride(from: 2, to: image.pixelsWide - 2, by: 4) {
            for y in stride(from: 2, to: image.pixelsHigh - 2, by: 4) {
                guard let read = image.colorAt(x: x, y: y) else { continue }
                guard let known = first else { first = read; continue }
                if differ(known, read) { return true }
            }
        }
        return false
    }

    private func differ(_ one: NSColor, _ other: NSColor) -> Bool {
        abs(one.redComponent - other.redComponent) > 0.02
            || abs(one.greenComponent - other.greenComponent) > 0.02
            || abs(one.blueComponent - other.blueComponent) > 0.02
    }

    // MARK: the picture the preview draws

    @Test func thePreviewDrawsTheDiagramAndNotABlankRectangle() throws {
        let (_, useCases) = aProject()
        _ = useCases.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let subject = aSubject(from: useCases)

        let drawn = try #require(
            hostedDrawing(
                of: FormingPicture(subject: subject, layout: aLayout(over: subject)),
                width: 640,
                height: 420
            )
        )

        #expect(hasContent(drawn.image))
    }

    @Test func theBoundsCoverWhatTheReportPlaced() {
        let layout = LayOutModelResponse(
            components: [LaidOutComponent(id: "a", x: 100, y: 200)],
            zones: []
        )

        let rect = LayoutReportBounds.rect(of: layout)

        #expect(rect?.contains(CGPoint(x: 100, y: 200)) == true)
        #expect(LayoutReportBounds.rect(of: LayOutModelResponse(components: [], zones: [])) == nil)
    }

    // MARK: the fit

    /// The canvas takes over at the fit the preview drew, so the picture does
    /// not move when the load finishes.
    @Test func thePreviewFitsTheWayZoomToFitFits() {
        let session = LayoutPreview.session()
        let column = CGSize(width: 900, height: 600)

        let canvas = CanvasState()
        canvas.visibleSize = column
        CanvasGestures(session: session, canvas: canvas).zoomToFit()

        let layout = LayOutModelResponse(
            components: session.canvas.components.map {
                LaidOutComponent(id: $0.id, x: $0.x, y: $0.y)
            },
            zones: session.canvas.zones.map {
                LaidOutZone(id: $0.id, x: $0.x, y: $0.y, width: $0.width, height: $0.height)
            }
        )
        let fit = CanvasTransform().fitting(LayoutReportBounds.rect(of: layout) ?? .zero, in: column)

        #expect(fit == canvas.transform)
    }

    /// A plan that widens the picture still fits the column, because the fit
    /// runs on every redraw.
    @Test func everyRedrawFitsAgain() {
        let column = CGSize(width: 900, height: 600)
        let near = LayOutModelResponse(
            components: [LaidOutComponent(id: "a", x: 0, y: 0), LaidOutComponent(id: "b", x: 200, y: 0)],
            zones: []
        )
        let far = LayOutModelResponse(
            components: [LaidOutComponent(id: "a", x: 0, y: 0), LaidOutComponent(id: "b", x: 4000, y: 0)],
            zones: []
        )

        let first = CanvasTransform().fitting(LayoutReportBounds.rect(of: near) ?? .zero, in: column)
        let second = CanvasTransform().fitting(LayoutReportBounds.rect(of: far) ?? .zero, in: column)

        #expect(second.zoom < first.zoom)
    }

    // MARK: the sampling

    /// The search reports on its own clock, and the window draws every report
    /// it makes, plus the last one whatever the interval says.
    @Test func reportsAtTheClockRateRedrawTheWindowAtTheIntervalAndOnceMoreForTheLast() {
        let (session, useCases) = aProject()
        _ = useCases.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let subject = aSubject(from: useCases)
        useCases.layoutProgress?.describe(subject)

        let clock = FakeClock()
        let sampler = session.watchTheLayout(now: { clock.reading() })
        for step in 0 ..< 10 {
            useCases.layoutProgress?.report(aLayout(over: subject, shiftedBy: Double(step)))
            clock.advance(by: LayoutProgress.reportInterval)
        }
        let atTheClockRate = sampler.redrawCount
        session.stopWatchingTheLayout()

        #expect(atTheClockRate == 10)
        #expect(sampler.redrawCount == 11)
        #expect(sampler.latest?.components.first?.x == subject.components[0].x + 9)
    }

    /// A report the window has not drawn yet is replaced, not queued: fifty
    /// reports inside one interval ask for one redraw, and that redraw draws
    /// the fiftieth.
    @Test func reportsInsideOneIntervalAreReplacedAndNotQueued() {
        let (session, useCases) = aProject()
        _ = useCases.importArchitecture().execute(ImportArchitectureRequest(text: payments))
        let subject = aSubject(from: useCases)
        useCases.layoutProgress?.describe(subject)

        let clock = FakeClock()
        let sampler = session.watchTheLayout(now: { clock.reading() })
        for step in 0 ..< 50 {
            useCases.layoutProgress?.report(aLayout(over: subject, shiftedBy: Double(step)))
        }
        let sampled = sampler.redrawCount
        session.stopWatchingTheLayout()

        #expect(sampled == 1)
        #expect(sampler.redrawCount == 2)
        #expect(sampler.latest?.components.first?.x == subject.components[0].x + 49)
    }

    /// The search's interval and the preview's interval are one number.
    @Test func theSamplerDrawsAtTheRateTheSearchReportsAt() {
        #expect(LayoutPreviewSampler.redrawInterval == LayoutProgress.reportInterval)
    }

    /// The interval is the rule, and the clock the sampler reads is its own,
    /// so a test states the rule without waiting.
    @Test func theSamplerRedrawsOncePerInterval() {
        let counted = Counted()
        let clock = FakeClock()
        let sampler = LayoutPreviewSampler(now: { clock.reading() }, redraw: { counted.add() })
        let layout = LayOutModelResponse(components: [LaidOutComponent(id: "a", x: 1, y: 1)], zones: [])

        sampler.receive(layout)
        clock.advance(by: LayoutPreviewSampler.redrawInterval / 2)
        sampler.receive(layout)
        clock.advance(by: LayoutPreviewSampler.redrawInterval)
        sampler.receive(layout)

        #expect(counted.count() == 2)
    }

    // MARK: the window

    /// The preview replaces the canvas while the search runs, so there is no
    /// selection, no drag and no panel over it, and it goes when the canvas
    /// takes over.
    @Test func thePreviewReplacesTheCanvasWhileTheSearchRuns() async {
        let (session, useCases) = aProject()
        await session.open(root: "/work")
        let subject = aSubject(from: useCases)
        useCases.layoutProgress?.describe(subject)

        #expect(session.model != nil)
        #expect(session.layoutPreview == nil)

        _ = session.watchTheLayout()
        useCases.layoutProgress?.report(aLayout(over: subject))
        session.stopWatchingTheLayout()
        // The redraw hops to the main actor, so it lands on the next turn.
        await Task.yield()
        await Task.yield()

        #expect(session.layoutPreview != nil)

        session.forgetTheLayoutPreview()
        #expect(session.layoutPreview == nil)
    }

    /// Lay Out on an open system states the same subject as opening one, so
    /// it draws the same preview.
    @Test func layingOutAnOpenSystemAgainStatesTheSubject() async {
        let (session, useCases) = aProject()
        await session.open(root: "/work")

        await session.layOutDiagram()

        #expect(
            useCases.layoutProgress?.subject?.components.map(\.name) == ["Orders API", "Orders store"]
        )
    }
}

/// Counts what a sampler asked for.
private final class Counted: @unchecked Sendable {
    private let lock = NSLock()
    private var total = 0
    func add() { lock.lock(); total += 1; lock.unlock() }
    func count() -> Int { lock.lock(); defer { lock.unlock() }; return total }
}

/// A clock a test moves by hand.
private final class FakeClock: @unchecked Sendable {
    private let lock = NSLock()
    private var seconds: TimeInterval = 0
    func reading() -> TimeInterval { lock.lock(); defer { lock.unlock() }; return seconds }
    func advance(by step: TimeInterval) { lock.lock(); seconds += step; lock.unlock() }
}
