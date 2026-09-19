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

/// A view in a window the way the application builds one: a hosting
/// controller, so SwiftUI installs the toolbar and the titlebar accessories
/// the sidebar's search field sits in.
///
/// The test runner starts with no active app. A window of a background app
/// draws its content at a much lower priority, so a sheet on it can take
/// far longer than a second to draw. This call activates the app the way a
/// person opening the window always has one, so every window this function
/// returns draws its content at full speed.
@MainActor
func hostedWindow(of view: some View, width: CGFloat = 1400, height: CGFloat = 900) -> NSWindow {
    // The test host starts with the `.prohibited` activation policy, which
    // holds no window key no matter how often a window asks. `.regular` is
    // the policy the application itself carries, so it is the one that
    // makes a hosted window behave the way the person's window does.
    if NSApp.activationPolicy() != .regular {
        NSApp.setActivationPolicy(.regular)
    }
    NSApp.activate(ignoringOtherApps: true)
    let controller = NSHostingController(rootView: view)
    let window = NSWindow(
        contentRect: NSRect(x: 0, y: 0, width: width, height: height),
        styleMask: [.titled, .closable, .resizable, .miniaturizable, .fullSizeContentView],
        backing: .buffered,
        defer: false
    )
    window.contentViewController = controller
    window.setContentSize(NSSize(width: width, height: height))
    window.makeKeyAndOrderFront(nil)
    window.contentView?.layoutSubtreeIfNeeded()
    RunLoop.current.run(until: Date().addingTimeInterval(1.2))
    window.contentView?.layoutSubtreeIfNeeded()
    return window
}
