import CoreServices
import Foundation

/// Reports that a file under a project directory changed.
///
/// It holds no rule and answers no question: it says only that something
/// changed, and `ProjectSession` decides what that means.
@MainActor
protocol ProjectWatching: AnyObject {
    func watch(directory: String, onChange: @escaping () -> Void)
    func stop()
}

/// Watches a directory with `FSEvents`.
///
/// `FSEvents` reports a write into a file that already exists, which a
/// `DispatchSource` on the directory does not. A text editor that saves in
/// place is the common case, so this application needs the file events.
@MainActor
final class FSEventsProjectWatcher: ProjectWatching {
    /// Read by `deinit`, which cannot enter the main actor. Every other
    /// access is main-actor isolated, so no two of them race.
    private nonisolated(unsafe) var stream: FSEventStreamRef?
    private var onChange: (() -> Void)?

    /// How long `FSEvents` gathers events before it reports them. A short wait
    /// joins the several writes one save makes into one report.
    private static let latency = 0.3

    func watch(directory: String, onChange: @escaping () -> Void) {
        stop()
        self.onChange = onChange

        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )

        let callback: FSEventStreamCallback = { _, info, _, _, _, _ in
            guard let info else { return }
            let watcher = Unmanaged<FSEventsProjectWatcher>.fromOpaque(info)
                .takeUnretainedValue()
            // The stream reports on the main queue, and the session it calls
            // is main-actor isolated.
            MainActor.assumeIsolated { watcher.report() }
        }

        guard let stream = FSEventStreamCreate(
            nil,
            callback,
            &context,
            [directory] as CFArray,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            Self.latency,
            UInt32(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer)
        ) else { return }

        self.stream = stream
        FSEventStreamSetDispatchQueue(stream, DispatchQueue.main)
        FSEventStreamStart(stream)
    }

    func stop() {
        onChange = nil
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
    }

    private func report() {
        onChange?()
    }

    deinit {
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
    }
}
