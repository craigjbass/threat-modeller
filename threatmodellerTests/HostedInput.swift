import AppKit
import SwiftUI

/// What a test needs to send a click into a real window and to read what
/// answered it.
///
/// A layout test measures frames, and a frame says nothing about what takes
/// the click that lands on it. #177: every column kept its frame and the
/// palette took no input at all. These functions read the answer AppKit gives.

/// Every view of this kind under this one, in the order AppKit holds them.
@MainActor
func views<T: NSView>(of kind: T.Type, in view: NSView) -> [T] {
    var found: [T] = []
    if let match = view as? T { found.append(match) }
    for child in view.subviews { found += views(of: kind, in: child) }
    return found
}

/// The first view of this kind under this one, or nil.
@MainActor
func firstView<T: NSView>(of kind: T.Type, in view: NSView) -> T? {
    views(of: kind, in: view).first
}

/// True while this view is the container or sits under it.
@MainActor
func isInside(_ view: NSView, _ container: NSView) -> Bool {
    var walked: NSView? = view
    while let node = walked {
        if node === container { return true }
        walked = node.superview
    }
    return false
}

/// Every view from this one up to the window, named, so a failure says what
/// answered the click.
@MainActor
func viewChain(from view: NSView?) -> String {
    guard let view else { return "nothing" }
    var names: [String] = []
    var walked: NSView? = view
    while let node = walked {
        names.append("\(type(of: node))")
        walked = node.superview
    }
    return names.joined(separator: " < ")
}

/// Lets AppKit and SwiftUI draw, so a change made here shows in the window.
@MainActor
func settle(_ window: NSWindow, _ seconds: TimeInterval = 0.6) {
    window.contentView?.layoutSubtreeIfNeeded()
    RunLoop.current.run(until: Date().addingTimeInterval(seconds))
    window.contentView?.layoutSubtreeIfNeeded()
}

/// Sends one press and one release at a point in window coordinates.
///
/// A double click is one call with a count of two, after a call with a count
/// of one, the way AppKit delivers it.
@MainActor
func click(_ window: NSWindow, at point: NSPoint, count: Int = 1) {
    for type in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
        guard let event = NSEvent.mouseEvent(
            with: type,
            location: point,
            modifierFlags: [],
            timestamp: ProcessInfo.processInfo.systemUptime,
            windowNumber: window.windowNumber,
            context: nil,
            eventNumber: 0,
            clickCount: count,
            pressure: type == .leftMouseDown ? 1 : 0
        ) else { continue }
        window.sendEvent(event)
    }
    RunLoop.current.run(until: Date().addingTimeInterval(0.2))
}

/// Sends a Return key press to this window: one `keyDown`, one `keyUp`.
///
/// AppKit runs the default button's action for a Return press, the same
/// control `.keyboardShortcut(.defaultAction)` names. A sheet's own close
/// button draws through SwiftUI's platform bridge, which answers no
/// accessibility identifier and builds no plain `NSButton` a test can find
/// and press, so a test presses Return instead.
@MainActor
func pressReturn(_ window: NSWindow) {
    for type in [NSEvent.EventType.keyDown, .keyUp] {
        guard let event = NSEvent.keyEvent(
            with: type,
            location: .zero,
            modifierFlags: [],
            timestamp: ProcessInfo.processInfo.systemUptime,
            windowNumber: window.windowNumber,
            context: nil,
            characters: "\r",
            charactersIgnoringModifiers: "\r",
            isARepeat: false,
            keyCode: 36
        ) else { continue }
        window.sendEvent(event)
    }
    RunLoop.current.run(until: Date().addingTimeInterval(0.2))
}

/// A view in a window the way the application builds one: a hosting
/// controller, so SwiftUI installs the toolbar and the titlebar accessories
/// the sidebar's search field sits in.
@MainActor
func hostedWindow(of view: some View, width: CGFloat = 1400, height: CGFloat = 900) -> NSWindow {
    let controller = NSHostingController(rootView: view)
    // Without this, the controller re-asserts SwiftUI's own idea of the
    // content's ideal size onto the window on a later layout pass, and a
    // window this test just set back to its own requested size shrinks
    // again on its own.
    controller.sizingOptions = []
    let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: width, height: height),
        styleMask: [.titled, .closable, .resizable, .miniaturizable, .fullSizeContentView],
        backing: .buffered,
        defer: false
    )
    window.contentViewController = controller
    window.setContentSize(NSSize(width: width, height: height))
    window.makeKeyAndOrderFront(nil)
    // AppKit cascades a new window clear of the ones already on screen, and
    // clips its size to what is left once enough windows crowd the display.
    // A test that runs beside others needs the size it asked for, not what
    // cascading left, so this puts the window back at its own corner.
    window.setFrame(NSRect(x: 0, y: 0, width: width, height: height), display: true)
    window.contentView?.layoutSubtreeIfNeeded()
    RunLoop.current.run(until: Date().addingTimeInterval(1.2))
    window.contentView?.layoutSubtreeIfNeeded()
    return window
}
