import AppKit
import SwiftUI
import Testing
import ThreatModelKit
@testable import threatmodeller

/// What each panel must fit inside.
///
/// `NavigationSplitView` states a minimum width for every column
/// (`ProjectColumns`). A panel that takes more room than its column gives
/// pushes the rest of that column out of the window, where the user cannot
/// reach it. These tests state the room each panel may take.
///
/// The pictures come from a hosting view in an offscreen window, not from
/// `ImageRenderer`. `ImageRenderer` draws nothing inside a `ScrollView`'s
/// `LazyVStack`, so it cannot see a threat card at all.
@MainActor
struct LayoutFitTests {
    /// The narrowest the sidebar column ever gets.
    private static let sidebarMinimumWidth: CGFloat = 300

    /// A window height this application must still be usable at.
    private static let smallColumnHeight: CGFloat = 500

    /// The narrowest the canvas column ever gets.
    private static let canvasMinimumWidth: CGFloat = 400

    /// The narrowest the right sidebar ever gets.
    private static let narrowestSidebarWidth: CGFloat = 280

    /// The margin the canvas keeps from the window's leading edge once the
    /// palette column is collapsed and the canvas starts at that edge.
    private static let windowEdgeMargin: CGFloat = 14

    // MARK: a drawn view

    private func hosted(
        _ view: some View,
        width: CGFloat,
        height: CGFloat
    ) -> (image: NSBitmapImageRep, scale: Int)? {
        hostedDrawing(of: view, width: width, height: height)
    }

    private func colour(_ image: NSBitmapImageRep, x: Int, y: Int) -> (r: Double, g: Double, b: Double)? {
        guard let read = image.colorAt(x: x, y: y) else { return nil }
        return (Double(read.redComponent), Double(read.greenComponent), Double(read.blueComponent))
    }

    /// True when every pixel in the range is one colour, which tells an empty
    /// margin from a control drawn under the window's edge.
    private func isUniform(
        _ image: NSBitmapImageRep,
        columns: Range<Int>,
        rows: Range<Int>
    ) -> Bool {
        var first: (r: Double, g: Double, b: Double)?
        for x in columns {
            for y in rows {
                guard let read = colour(image, x: x, y: y) else { continue }
                guard let known = first else { first = read; continue }
                if abs(known.r - read.r) > 0.02
                    || abs(known.g - read.g) > 0.02
                    || abs(known.b - read.b) > 0.02 {
                    return false
                }
            }
        }
        return true
    }

    /// True when two pictures draw the same thing in the same band.
    private func bandsMatch(
        _ one: NSBitmapImageRep,
        _ other: NSBitmapImageRep,
        columns: Range<Int>,
        rows: Range<Int>
    ) -> Bool {
        for x in columns {
            for y in rows {
                guard let left = colour(one, x: x, y: y), let right = colour(other, x: x, y: y) else {
                    continue
                }
                if abs(left.r - right.r) > 0.02
                    || abs(left.g - right.g) > 0.02
                    || abs(left.b - right.b) > 0.02 {
                    return false
                }
            }
        }
        return true
    }

    // MARK: what a threat card looks like

    /// The colour of the severity badge a threat card draws, taken from the
    /// palette itself rather than written down, so a palette change does not
    /// make this test lie.
    private func severityBadgeColour() throws -> (r: Double, g: Double, b: Double) {
        let swatch = Color(nsColor: .controlBackgroundColor)
            .overlay(RiskPalette.background(forLevelId: "high"))
        let drawn = try #require(hosted(swatch, width: 40, height: 40))
        return try #require(colour(drawn.image, x: drawn.image.pixelsWide / 2, y: drawn.image.pixelsHigh / 2))
    }

    /// True when the picture holds a run of the badge colour long enough to be
    /// the badge behind a threat card's severity, and not a coloured digit in
    /// the risk summary, whose glyphs are a few points wide.
    private func drawsASeverityBadge(
        _ image: NSBitmapImageRep,
        like badge: (r: Double, g: Double, b: Double),
        scale: Int
    ) -> Bool {
        let runNeeded = 20 * scale
        for y in 0..<image.pixelsHigh {
            var run = 0
            for x in 0..<image.pixelsWide {
                guard let read = colour(image, x: x, y: y) else { run = 0; continue }
                let matches = abs(read.r - badge.r) < 0.03
                    && abs(read.g - badge.g) < 0.03
                    && abs(read.b - badge.b) < 0.03
                run = matches ? run + 1 : 0
                if run >= runNeeded { return true }
            }
        }
        return false
    }

    // MARK: the sidebar

    /// The header is the only control that closes the pathway panel. An open
    /// panel is taller than a small column, and the column used to overflow
    /// and carry that header above the top of the window, so nothing could
    /// close the panel again. The header must stay where it is drawn when the
    /// panel is closed.
    @Test func theMitigationsPanelHeaderStaysAtTheTopWhenThePanelIsOpen() throws {
        let session = LayoutPreview.sessionWithEveryMitigationOn()

        let open = try #require(
            hosted(
                ThreatSidebar(session: session, pathwayExpanded: true),
                width: Self.sidebarMinimumWidth,
                height: Self.smallColumnHeight
            )
        )
        let closed = try #require(
            hosted(
                ThreatSidebar(session: session, pathwayExpanded: false),
                width: Self.sidebarMinimumWidth,
                height: Self.smallColumnHeight
            )
        )

        // The words "Pathway mitigations" sit in this band. The chevron before
        // them and the state after them differ between the two, so the band
        // stops short of both.
        let scale = open.scale
        #expect(
            bandsMatch(
                open.image,
                closed.image,
                columns: (30 * scale)..<(200 * scale),
                rows: 0..<(34 * scale)
            )
        )
    }

    /// The same column with the panel closed already draws a card. Without
    /// this, the test above could pass on a model that raises no threats, or
    /// on a picture that holds nothing at all.
    @Test func theSidebarDrawsAThreatCardWithTheMitigationsPanelClosed() throws {
        let session = LayoutPreview.sessionWithEveryMitigationOn()
        let badge = try severityBadgeColour()

        let drawn = try #require(
            hosted(
                ThreatSidebar(session: session, pathwayExpanded: false),
                width: Self.sidebarMinimumWidth,
                height: Self.smallColumnHeight
            )
        )

        #expect(drawsASeverityBadge(drawn.image, like: badge, scale: drawn.scale))
    }

    /// A mitigation row carries a mode picker and a slider. Their widths are
    /// fixed, and together they are wider than the column's own minimum, so
    /// the row drew under both edges of the column.
    @Test func theMitigationsPanelDrawsInsideItsNarrowestColumn() throws {
        let session = LayoutPreview.sessionWithEveryMitigationOn()

        // The ground goes behind the whole column, not behind the panel, so
        // every pixel outside a control is one colour and a control drawn in
        // the margin is the only thing that can break it.
        let drawn = try #require(
            hosted(
                PathwayMitigationsPanel(session: session, isExpanded: true)
                    .frame(width: Self.sidebarMinimumWidth, height: 700)
                    .background(Color(nsColor: .controlBackgroundColor)),
                width: Self.sidebarMinimumWidth,
                height: 700
            )
        )

        // The panel's own padding is 12, so the outermost 4 points are margin
        // on both sides and nothing the panel draws may reach them.
        let edge = 4 * drawn.scale
        let right = drawn.image.pixelsWide
        let rows = 0..<drawn.image.pixelsHigh
        #expect(isUniform(drawn.image, columns: 0..<edge, rows: rows), "the panel drew under the leading edge")
        #expect(
            isUniform(drawn.image, columns: (right - edge)..<right, rows: rows),
            "the panel drew under the trailing edge"
        )
    }

    // MARK: the canvas

    /// Every selection editor fits the narrowest sidebar column.
    ///
    /// The editor is a column of fields in the right sidebar, which is 280
    /// points at its narrowest. Nothing it draws may reach the margin at
    /// either edge of that column.
    @Test func everySelectionEditorFitsTheNarrowestSidebarColumn() throws {
        let session = LayoutPreview.session()
        let component = try #require(session.canvas.components.first)
        let connection = try #require(session.canvas.connections.first)
        _ = session.addZone(x: 0, y: 0, width: 400, height: 300)
        let zone = try #require(session.canvas.zones.first)

        let editors: [(String, AnyView)] = [
            ("component", AnyView(ComponentPanel(session: session, component: component))),
            ("zone", AnyView(ZonePanel(session: session, zone: zone))),
            ("connection", AnyView(ConnectionPanel(session: session, connection: connection)))
        ]

        for (name, editor) in editors {
            let drawn = try #require(
                hosted(
                    editor
                        .frame(width: Self.narrowestSidebarWidth, height: Self.smallColumnHeight)
                        .background(Color(nsColor: .controlBackgroundColor)),
                    width: Self.narrowestSidebarWidth,
                    height: Self.smallColumnHeight
                ),
                "the \(name) editor drew nothing"
            )

            // The editor's own padding is 16, so the outermost 4 points are
            // margin and nothing the editor draws may reach them.
            let edge = 4 * drawn.scale
            #expect(
                isUniform(drawn.image, columns: 0..<edge, rows: 0..<drawn.image.pixelsHigh),
                "the \(name) editor drew under the leading edge"
            )
        }
    }

    /// Collapsing the palette column puts the canvas against the window's
    /// leading edge. The Draw zone control must keep a margin from it.
    @Test func theCanvasToolbarKeepsAMarginFromTheWindowEdge() throws {
        let session = LayoutPreview.session()

        let drawn = try #require(
            hosted(
                CanvasView(session: session, canvas: CanvasState()),
                width: 1200,
                height: 700
            )
        )

        let margin = Int(Self.windowEdgeMargin) * drawn.scale
        // The toolbar sits at the top, so the top 60 points are what matters.
        #expect(isUniform(drawn.image, columns: 0..<margin, rows: 0..<(60 * drawn.scale)))
    }

    /// The bottom bar has the same window edge to keep clear of.
    @Test func theBottomBarKeepsAMarginFromTheWindowEdge() throws {
        let session = LayoutPreview.session()
        let canvas = LayoutPreview.canvasSelectingTheFirstComponent(of: session)

        let drawn = try #require(
            hosted(CanvasView(session: session, canvas: canvas), width: 1200, height: 700)
        )

        let margin = Int(Self.windowEdgeMargin) * drawn.scale
        let bottom = drawn.image.pixelsHigh
        // The bar draws its own background across the whole width, so only
        // rows inside the bar are read. A control in the margin breaks that
        // background; the background alone does not.
        #expect(isUniform(drawn.image, columns: 0..<margin, rows: (bottom - 30 * drawn.scale)..<bottom))
    }
}
