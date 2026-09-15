import AppKit
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Searching the palette stopped the application. These tests draw the
/// palette the way AppKit draws it, mid-search, so a fault in the list is a
/// failed test rather than a crash a person meets.
@MainActor
@Suite("Searching the technology palette")
struct PaletteSearchCrashTests {
    private func session() -> ThreatModelSession {
        ThreatModelSession(useCases: TestDependencies())
    }

    private func drawPalette(searching words: String) -> Bool {
        let session = session()
        let drawn = hostedDrawing(
            of: PaletteView(
                session: session,
                canvas: CanvasState(),
                searchText: words
            ),
            width: 260,
            height: 600
        )
        return drawn != nil
    }

    @Test func drawsWhileASearchNarrowsTheList() {
        #expect(drawPalette(searching: "ec2"))
    }

    @Test func drawsWhileASearchMatchesNothing() {
        #expect(drawPalette(searching: "nothing matches this"))
    }

    @Test func drawsWhileASearchMatchesManyProviders() {
        #expect(drawPalette(searching: "a"))
    }

    @Test func drawsAgainAfterTheSearchIsCleared() {
        #expect(drawPalette(searching: ""))
    }

    /// A person types one character at a time, and the list is rebuilt
    /// between each. The static draws above never rebuild it.
    @Test func drawsWhileAPersonTypesOneCharacterAtATime() {
        let typed = TypedSearch()
        let session = session()
        let host = NSHostingView(
            rootView: SearchingPalette(session: session, canvas: CanvasState(), typed: typed)
                .frame(width: 260, height: 600)
        )
        host.frame = CGRect(x: 0, y: 0, width: 260, height: 600)
        let window = NSWindow(
            contentRect: host.frame,
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.contentView = host
        window.orderBack(nil)

        for word in ["e", "ec", "ec2", "ec", "e", "", "s3", "saas", "s", ""] {
            typed.words = word
            host.layoutSubtreeIfNeeded()
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        window.orderOut(nil)

        #expect(typed.words.isEmpty)
    }
}

/// What a test types, so the palette is rebuilt between each character.
@MainActor
@Observable
final class TypedSearch {
    var words = ""
}

/// The palette, with its search field driven by a test.
@MainActor
private struct SearchingPalette: View {
    let session: ThreatModelSession
    let canvas: CanvasState
    let typed: TypedSearch

    /// The list is the same list across each change, the way it is while a
    /// person types, so SwiftUI diffs it in place rather than building a new
    /// one.
    @State private var selected: String?

    var body: some View {
        PaletteList(
            session: session,
            canvas: canvas,
            searchText: typed.words,
            selected: $selected,
            edit: { _ in }
        )
    }
}

/// Opening and closing a category stopped the application. The rows a
/// category shows are rows of the list itself, so opening one adds rows to a
/// section rather than changing what one row holds.
@MainActor
@Suite("Opening and closing a palette category")
struct PaletteCategoryCrashTests {
    /// What a test presses, so the list is diffed in place between presses.
    @MainActor
    @Observable
    final class OpenCategories {
        var open: Set<String> = []
    }

    private struct OpeningPalette: View {
        let session: ThreatModelSession
        let canvas: CanvasState
        let opened: OpenCategories
        @State private var selected: String?

        var body: some View {
            PaletteList(
                session: session,
                canvas: canvas,
                searchText: "",
                selected: $selected,
                edit: { _ in },
                openCategories: opened.open
            )
        }
    }

    @Test func drawsWhileACategoryIsOpenedAndClosedTwice() {
        let opened = OpenCategories()
        let session = ThreatModelSession(useCases: TestDependencies())
        let host = NSHostingView(
            rootView: OpeningPalette(session: session, canvas: CanvasState(), opened: opened)
                .frame(width: 260, height: 600)
        )
        host.frame = CGRect(x: 0, y: 0, width: 260, height: 600)
        let window = NSWindow(
            contentRect: host.frame,
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.contentView = host
        window.orderBack(nil)

        // The provider whose category is named after the provider is the one
        // a person met the crash on.
        let key = "saas:saas"
        for open in [true, false, true, false, true] {
            opened.open = open ? [key] : []
            host.layoutSubtreeIfNeeded()
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        window.orderOut(nil)

        #expect(opened.open.isEmpty == false)
    }
}
