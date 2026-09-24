import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

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
        closeOnExec(output)
        closeOnExec(errors)
        process.standardOutput = output
        process.standardError = errors

        let processEnded = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in processEnded.signal() }

        beforeItStarts?(process)
        try spawnLock.withLock {
            closeEveryOtherDescriptorOnExec()
            try process.run()
        }

        let killed = KilledByTheTimer()
        let ended = DispatchSemaphore(value: 0)
        let timer = Thread {
            guard ended.wait(timeout: .now() + timeout) == .timedOut else { return }
            killed.set()
            process.terminate()
        }
        timer.start()

        let errorBytes = Bytes()
        let readTheErrors = DispatchSemaphore(value: 0)
        let reader = Thread {
            errorBytes.set(errors.fileHandleForReading.readDataToEndOfFile())
            readTheErrors.signal()
        }
        reader.start()
        let outputBytes = output.fileHandleForReading.readDataToEndOfFile()
        readTheErrors.wait()
        processEnded.wait()
        ended.signal()

        return ChildProcessAnswer(
            output: String(decoding: outputBytes, as: UTF8.self),
            errors: String(decoding: errorBytes.value, as: UTF8.self),
            exitCode: process.terminationStatus,
            timerKilledIt: killed.value
        )
    }
}

private let spawnLock = NSLock()

/// Keeps every file and pipe this process holds out of the child about to
/// start, so a script another thread is still writing can run once its
/// writer closes it.
private func closeEveryOtherDescriptorOnExec() {
    #if os(Linux)
    guard let entries = try? FileManager.default.contentsOfDirectory(atPath: "/proc/self/fd") else { return }
    for entry in entries {
        guard let descriptor = Int32(entry), descriptor > 2 else { continue }
        let flags = fcntl(descriptor, F_GETFD)
        guard flags >= 0 else { continue }
        _ = fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC)
    }
    #endif
}

/// Keeps a pipe out of every other child spawned at the same moment.
private func closeOnExec(_ pipe: Pipe) {
    for handle in [pipe.fileHandleForReading, pipe.fileHandleForWriting] {
        let descriptor = handle.fileDescriptor
        _ = fcntl(descriptor, F_SETFD, fcntl(descriptor, F_GETFD) | FD_CLOEXEC)
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
