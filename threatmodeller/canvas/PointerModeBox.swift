import Foundation

/// Holds one pointer mode by reference.
///
/// `CanvasView` and `TreeCanvas` install their scroll monitor once, from
/// `.onAppear`, and the monitor's closure keeps running for the life of the
/// canvas. A plain `PointerMode` value is copied into that closure the
/// moment the closure is made, so a later change to the picker never reaches
/// it. This box stays the same object across every change, so the closure
/// reads today's mode each time a wheel event arrives.
@MainActor
final class PointerModeBox {
    var mode: PointerMode

    init(_ mode: PointerMode = .standard) {
        self.mode = mode
    }
}
