import Foundation

/// What one child process wrote and how it ended.
public struct ChildProcessAnswer: Sendable, Equatable {
    public let output: String
    public let errors: String
    public let exitCode: Int32
    public let timerKilledIt: Bool
}

/// Runs one child process with a timeout.
///
/// The runner reads every pipe first and waits second, so a child that fills a
/// pipe buffer still ends. A timer kills a child that stays past the timeout,
/// and the answer says the timer did it.
public enum ChildProcess {
    public static func run(
        _ executable: String,
        _ arguments: [String],
        environment: [String: String],
        timeout: TimeInterval,
        readsNoInput: Bool = false,
        beforeItStarts: ((Process) -> Void)? = nil
    ) throws -> ChildProcessAnswer {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = environment
        if readsNoInput { process.standardInput = FileHandle.nullDevice }

        let output = Pipe()
        let errors = Pipe()
        process.standardOutput = output
        process.standardError = errors

        beforeItStarts?(process)
        try process.run()

        let killed = KilledByTheTimer()
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak process] in
            guard let process, process.isRunning else { return }
            killed.set()
            process.terminate()
        }

        let errorBytes = Bytes()
        let readTheErrors = DispatchSemaphore(value: 0)
        let reader = Thread {
            errorBytes.set(errors.fileHandleForReading.readDataToEndOfFile())
            readTheErrors.signal()
        }
        reader.start()
        let outputBytes = output.fileHandleForReading.readDataToEndOfFile()
        readTheErrors.wait()
        process.waitUntilExit()

        return ChildProcessAnswer(
            output: String(decoding: outputBytes, as: UTF8.self),
            errors: String(decoding: errorBytes.value, as: UTF8.self),
            exitCode: process.terminationStatus,
            timerKilledIt: killed.value
        )
    }
}

private final class KilledByTheTimer: @unchecked Sendable {
    private let lock = NSLock()
    private var killed = false

    func set() {
        lock.lock()
        defer { lock.unlock() }
        killed = true
    }

    var value: Bool {
        lock.lock()
        defer { lock.unlock() }
        return killed
    }
}

private final class Bytes: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes = Data()

    func set(_ bytes: Data) {
        lock.lock()
        defer { lock.unlock() }
        self.bytes = bytes
    }

    var value: Data {
        lock.lock()
        defer { lock.unlock() }
        return bytes
    }
}
