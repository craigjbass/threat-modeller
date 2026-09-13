import Foundation

/// Where the layout search says how it is going.
///
/// A large model takes long enough that a person wants to see something. The
/// search holds only geometry, so what it reports is the shape of the picture
/// forming: where each component sits and how big each zone is. It carries no
/// name and no technology, because the layout knows neither.
///
/// Locked, because the search may run off the main actor and the listener is
/// on it.
public final class LayoutProgress: @unchecked Sendable {
    public typealias Listener = @Sendable (LayOutModelResponse) -> Void

    private let lock = NSLock()
    private var listener: Listener?

    public init() {}

    /// Who hears the next report, or nil for nobody. Setting it replaces
    /// whoever heard it before, because one window draws one load.
    public func listen(_ listener: Listener?) {
        lock.lock()
        defer { lock.unlock() }
        self.listener = listener
    }

    /// What the search calls. It costs nothing when nobody is listening.
    public func report(_ layout: LayOutModelResponse) {
        lock.lock()
        let heard = listener
        lock.unlock()
        heard?(layout)
    }
}
