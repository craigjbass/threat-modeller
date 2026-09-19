import Foundation

/// What a preview draws the layout reports over.
///
/// A layout report holds geometry alone: an identifier and a place for each
/// component, and a rectangle for each zone. A picture needs the name, the
/// shape, the provider, the category and the flows as well, and the search
/// knows none of them. So the use case that runs the search states the
/// subject, and the preview draws the subject at the reported coordinates.
public struct LayoutSubject: Equatable, Sendable {
    public let components: [ViewedComponent]
    public let connections: [ViewedConnection]
    public let zones: [ViewedZone]

    public init(
        components: [ViewedComponent],
        connections: [ViewedConnection],
        zones: [ViewedZone]
    ) {
        self.components = components
        self.connections = connections
        self.zones = zones
    }

    /// The subject one model draws as. The coordinates here are the model's
    /// own; a report replaces them.
    public static func of(_ model: ThreatModel, catalogue: TechnologyCatalogue) -> LayoutSubject {
        LayoutSubject(
            components: ViewedModel.components(of: model, catalogue: catalogue),
            connections: ViewedModel.connections(of: model),
            zones: ViewedModel.zones(of: model)
        )
    }
}

/// Where the layout search says how it is going.
///
/// A large model takes long enough that a person wants to see something. The
/// caller that runs the search states the subject first, so a listener that
/// hears a report always has a picture to draw it over.
///
/// Locked, because the search may run off the main actor and the listener is
/// on it.
public final class LayoutProgress: @unchecked Sendable {
    public typealias Listener = @Sendable (LayOutModelResponse) -> Void

    /// How often the window's sampler turns reports into a redraw, at most.
    /// `docs/superpowers/specs/2026-09-17-layout-preview-design.md` states the
    /// measurement behind it.
    public static let reportInterval: TimeInterval = 1.0 / 16

    private let lock = NSLock()
    private var listener: Listener?
    private var drawnSubject: LayoutSubject?

    public init() {}

    /// Who hears the next report, or nil for nobody. Setting it replaces
    /// whoever heard it before, because one window draws one load.
    public func listen(_ listener: Listener?) {
        lock.lock()
        defer { lock.unlock() }
        self.listener = listener
    }

    /// What the search's caller states before the search starts, or nil to
    /// forget the last one.
    public func describe(_ subject: LayoutSubject?) {
        lock.lock()
        defer { lock.unlock() }
        drawnSubject = subject
    }

    /// What the reports are about, or nil when nobody has stated it.
    public var subject: LayoutSubject? {
        lock.lock()
        defer { lock.unlock() }
        return drawnSubject
    }

    /// What the search calls. It costs nothing when nobody is listening.
    public func report(_ layout: LayOutModelResponse) {
        lock.lock()
        let heard = listener
        lock.unlock()
        heard?(layout)
    }
}
