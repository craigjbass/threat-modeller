import AppKit

/// What installs and removes one `NSEvent` local monitor.
///
/// `CanvasView` and `TreeCanvas` call this to read the scroll wheel, because
/// SwiftUI hands a view no scroll event. A real monitor gives back an opaque
/// token with no way to ask how many are active, so a test's fake counts
/// them instead, to state that a stage switch and back leaves one monitor
/// running, not two.
@MainActor
protocol LocalEventMonitoring {
    func addLocalMonitor(
        matching mask: NSEvent.EventTypeMask,
        handler: @escaping (NSEvent) -> NSEvent?
    ) -> Any?

    func removeMonitor(_ monitor: Any)
}

/// The real monitor, over `NSEvent`'s own class methods.
struct AppKitEventMonitoring: LocalEventMonitoring {
    func addLocalMonitor(
        matching mask: NSEvent.EventTypeMask,
        handler: @escaping (NSEvent) -> NSEvent?
    ) -> Any? {
        NSEvent.addLocalMonitorForEvents(matching: mask, handler: handler)
    }

    func removeMonitor(_ monitor: Any) {
        NSEvent.removeMonitor(monitor)
    }
}
