/// Which pointing device the person drives the canvas with.
///
/// A trackpad gives a two finger scroll and a pinch, so the scroll pans and
/// the pinch zooms. A mouse gives a wheel and no pinch, so the wheel zooms
/// about the pointer, Shift-wheel pans left and right, and a middle-button
/// drag or a Space-drag pans. Both canvases read this one setting.
///
/// Declared `nonisolated`: the app target defaults every type to the main
/// actor, and this one is a plain value.
nonisolated enum PointerMode: String, CaseIterable, Identifiable, Sendable {
    case trackpad
    case mouse

    var id: String { rawValue }

    /// What the toolbar and the View menu call each mode.
    var name: String {
        switch self {
        case .trackpad: "Trackpad"
        case .mouse: "Mouse"
        }
    }

    /// What a person reads to know which mode to pick.
    var help: String {
        switch self {
        case .trackpad: "Two finger scroll pans. Pinch zooms."
        case .mouse: "The wheel zooms. Shift-wheel pans sideways. "
            + "A middle-button drag or a Space-drag pans."
        }
    }

    /// The mode a person starts in, and the mode a stored value that names no
    /// mode falls back to.
    static let standard = PointerMode.trackpad
}
