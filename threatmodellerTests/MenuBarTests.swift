import AppKit
import Testing
@testable import threatmodeller

/// The application's own menu bar, once its commands are installed.
///
/// #153: `CommandMenu("View")` opened a second top-level menu named View
/// beside the standard one AppKit already builds from `.sidebar` and
/// `.toolbar`. These tests state there is one menu named View, and that it
/// holds the application's own items in the order the design states.
@MainActor
@Suite("The menu bar")
struct MenuBarTests {
    private func mainMenu() throws -> NSMenu {
        try #require(NSApp.mainMenu)
    }

    private func submenu(titled title: String, in menu: NSMenu) throws -> NSMenu {
        try #require(menu.items.first { $0.title == title }?.submenu)
    }

    @Test func thereIsExactlyOneMenuTitledView() throws {
        let titles = try mainMenu().items.map(\.title)

        #expect(titles.filter { $0 == "View" }.count == 1)
    }

    @Test func noTwoTopLevelMenusShareATitle() throws {
        let titles = try mainMenu().items.map(\.title)

        #expect(titles.count == Set(titles).count)
    }

    @Test func theViewMenuHoldsTheStagesTheZoomCommandsAndThePointer() throws {
        let view = try submenu(titled: "View", in: mainMenu())
        let titles = view.items.map(\.title)

        #expect(titles.contains("Architecture"))
        #expect(titles.contains("Attack Trees"))
        #expect(titles.contains("Threats"))
        #expect(titles.contains("Controls"))
        #expect(titles.contains("Report"))
        #expect(titles.contains("Zoom In"))
        #expect(titles.contains("Zoom Out"))
        #expect(titles.contains("Actual Size"))
        #expect(titles.contains("Zoom to Fit"))
        #expect(titles.contains("Zoom to Selection"))
        #expect(titles.contains("Pointer"))
    }

    /// The design states the stages first, then zoom, then the pointer mode,
    /// then the system's own items (Enter Full Screen and the rest).
    @Test func theStagesComeBeforeTheZoomCommandsWhichComeBeforeThePointer() throws {
        let view = try submenu(titled: "View", in: mainMenu())
        let titles = view.items.map(\.title)

        let lastStage = try #require(titles.firstIndex(of: "Report"))
        let firstZoom = try #require(titles.firstIndex(of: "Zoom In"))
        let lastZoom = try #require(titles.firstIndex(of: "Zoom to Selection"))
        let pointer = try #require(titles.firstIndex(of: "Pointer"))

        #expect(lastStage < firstZoom)
        #expect(lastZoom < pointer)
    }

    @Test func everyStageAndZoomShortcutKeepsItsKey() throws {
        let view = try submenu(titled: "View", in: mainMenu())

        func key(_ title: String) -> String? {
            view.items.first { $0.title == title }?.keyEquivalent
        }

        #expect(key("Architecture") == "1")
        #expect(key("Attack Trees") == "2")
        #expect(key("Threats") == "3")
        #expect(key("Controls") == "4")
        #expect(key("Report") == "5")
        #expect(key("Zoom In") == "=")
        #expect(key("Zoom Out") == "-")
        #expect(key("Actual Size") == "0")
        #expect(key("Zoom to Fit") == "9")
    }
}
