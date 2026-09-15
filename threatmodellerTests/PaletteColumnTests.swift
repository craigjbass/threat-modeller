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

        #expect(hidden == .detailOnly)
        #expect(PaletteColumn.toggled(hidden) == .all)
    }

    /// A window that opens with the palette beside the diagram, and one that
    /// opens with the palette over it, both hide on the first press.
    @Test func aToggleFromAnyShowingStateHidesThePalette() {
        #expect(PaletteColumn.toggled(.all) == .detailOnly)
        #expect(PaletteColumn.toggled(.doubleColumn) == .detailOnly)
        #expect(PaletteColumn.toggled(.automatic) == .detailOnly)
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

    @Test func saysWhetherThePaletteIsOnScreen() {
        #expect(PaletteColumn.isShowing(.all))
        #expect(PaletteColumn.isShowing(.doubleColumn))
        #expect(PaletteColumn.isShowing(.detailOnly) == false)
    }
}
