import SwiftUI
import Testing
import TestSupport
@testable import threatmodeller

/// The sidebar button did nothing: the split view held no visibility for it
/// to write. These state what the toggle does to each state the split view
/// can be in.
@Suite("Showing and hiding the palette")
struct PaletteColumnTests {
    @Test func aToggleHidesThePaletteAndShowsItAgain() {
        let hidden = PaletteColumn.toggled(.all)

        #expect(hidden == .doubleColumn)
        #expect(PaletteColumn.toggled(hidden) == .all)
    }

    /// A window that opens with the palette beside the diagram hides it on
    /// the first press. `.doubleColumn` is the hidden state itself, so
    /// pressing again from there shows the palette, it never hides twice.
    @Test func aToggleFromAnyShowingStateHidesThePalette() {
        #expect(PaletteColumn.toggled(.all) == .doubleColumn)
    }

    /// #158: the three-column split this window draws does not honour
    /// `.detailOnly`, so a toggle never sets it, on any state it starts from.
    @Test func neverTogglesToDetailOnly() {
        #expect(PaletteColumn.toggled(.all) != .detailOnly)
        #expect(PaletteColumn.toggled(.doubleColumn) != .detailOnly)
        #expect(PaletteColumn.toggled(.automatic) != .detailOnly)
    }

    /// The window holds the state the sidebar button writes, so the button,
    /// the menu item and the key all change one thing.
    @MainActor
    @Test func theWindowHoldsWhatTheToggleWrites() {
        let session = ProjectSession(
            useCases: TestDependencies(),
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )

        #expect(PaletteColumn.isShowing(session.paletteColumns))

        session.togglePalette()
        #expect(PaletteColumn.isShowing(session.paletteColumns) == false)

        session.togglePalette()
        #expect(PaletteColumn.isShowing(session.paletteColumns))
    }

    /// #158: one toggle from the default hides the palette, and a second
    /// toggle shows it again.
    @MainActor
    @Test func isShowingIsFalseAfterOneToggleAndTrueAfterTwo() {
        let session = ProjectSession(
            useCases: TestDependencies(),
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )

        session.togglePalette()
        #expect(PaletteColumn.isShowing(session.paletteColumns) == false)

        session.togglePalette()
        #expect(PaletteColumn.isShowing(session.paletteColumns))
    }

    /// #158: the palette's shown or hidden state outlives the run, the way
    /// the pointer mode does.
    @MainActor
    @Test func remembersThePaletteVisibilityForTheNextSession() {
        let defaults = aTestDefaults()
        let useCases = TestDependencies()
        let first = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: defaults
        )

        first.togglePalette()
        #expect(PaletteColumn.isShowing(first.paletteColumns) == false)

        let second = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: defaults
        )

        #expect(PaletteColumn.isShowing(second.paletteColumns) == false)
    }

    @Test func saysWhetherThePaletteIsOnScreen() {
        #expect(PaletteColumn.isShowing(.all))
        #expect(PaletteColumn.isShowing(.doubleColumn) == false)
    }
}
