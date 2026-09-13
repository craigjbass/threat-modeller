import AppKit
import SwiftUI

/// Draws a view the way AppKit draws it, in an offscreen window.
///
/// `ImageRenderer` draws nothing inside a `ScrollView`'s `LazyVStack`: it lays
/// the view out with no scroll geometry, so the lazy stack never fills in and
/// the picture comes back blank. A hosting view in a window gives the real
/// geometry, so a scrolling view can be seen at all.
///
/// The scale is the backing scale the picture was made at, so a caller that
/// reads pixels can say what it wants in points.
@MainActor
func hostedDrawing(
    of view: some View,
    width: CGFloat,
    height: CGFloat
) -> (image: NSBitmapImageRep, scale: Int)? {
    let host = NSHostingView(rootView: view.frame(width: width, height: height))
    host.frame = CGRect(x: 0, y: 0, width: width, height: height)

    let window = NSWindow(
        contentRect: host.frame,
        styleMask: [.titled],
        backing: .buffered,
        defer: false
    )
    window.contentView = host
    window.orderBack(nil)
    host.layoutSubtreeIfNeeded()
    // A lazy stack fills in on the run loop, not in `layoutSubtreeIfNeeded`.
    RunLoop.current.run(until: Date().addingTimeInterval(0.4))

    guard let image = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return nil }
    host.cacheDisplay(in: host.bounds, to: image)
    window.orderOut(nil)

    return (image, max(1, image.pixelsWide / Int(width)))
}
