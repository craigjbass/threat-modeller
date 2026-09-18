import Foundation
import Testing
import ThreatModelKit

/// What every ATT&CK data gateway owes its callers.
///
/// `filesPresent` names every file the store holds right now, read through a
/// path the gateway itself does not own, so the contract can check what a
/// write actually left behind.
public func verifyAttackDataGatewayContract(
    directory: String,
    filesPresent: @escaping () -> [String],
    make: @escaping () -> AttackDataGateway
) {
    let gateway = make()
    #expect(gateway.directory == directory)

    // A file that was never written is not there.
    #expect(gateway.read(fileName: "groups.json") == nil)
    #expect(gateway.modified(fileName: "groups.json") == nil)

    // Writing then reading gives back what was written.
    #expect(throws: Never.self) { try gateway.write("one", fileName: "groups.json") }
    #expect(gateway.read(fileName: "groups.json") == "one")
    #expect(gateway.modified(fileName: "groups.json") != nil)

    // A second write of the same file name replaces the first.
    #expect(throws: Never.self) { try gateway.write("two", fileName: "groups.json") }
    #expect(gateway.read(fileName: "groups.json") == "two")

    // The directory the gateway names is the directory it writes into: the
    // file sits where a path built from that directory says it does.
    #expect(filesPresent().contains("groups.json"))

    // A write into a directory that does not exist yet still succeeds, and
    // the file it wrote reads back, from a second gateway made the same way.
    let second = make()
    #expect(throws: Never.self) { try second.write("three", fileName: "software.json") }
    #expect(second.read(fileName: "software.json") == "three")

    // After every write above, the store holds no file whose name begins
    // with a dot: a temporary name never survives the write that used it.
    #expect(filesPresent().filter { $0.hasPrefix(".") }.isEmpty)

    verifyNoReaderSeesAHalfWrittenFile(make: make, filesPresent: filesPresent)
}

/// A reader who reads while a write runs reads the whole old file or the
/// whole new file, never a mix of the two.
///
/// Sixteen readers poll at once, each in its own tight loop, so the odds of
/// one landing inside the write's window are high when that window exists.
private func verifyNoReaderSeesAHalfWrittenFile(
    make: () -> AttackDataGateway,
    filesPresent: () -> [String]
) {
    let gateway = make()
    let oldText = String(repeating: "a", count: 500_000)
    let newText = String(repeating: "b", count: 500_000)
    #expect(throws: Never.self) { try gateway.write(oldText, fileName: "big.json") }
    #expect(gateway.read(fileName: "big.json") == oldText)

    let writeInProgress = WriteInProgressFlag()
    let tornReadFlag = TornReadFlag()

    let writer = Thread {
        try? gateway.write(newText, fileName: "big.json")
        writeInProgress.finish()
    }
    writer.start()

    let readers = DispatchGroup()
    for _ in 0..<16 {
        readers.enter()
        DispatchQueue.global().async {
            while writeInProgress.isRunning {
                guard let read = gateway.read(fileName: "big.json") else { continue }
                if read != oldText && read != newText {
                    tornReadFlag.markTorn()
                }
            }
            readers.leave()
        }
    }
    readers.wait()

    #expect(gateway.read(fileName: "big.json") == newText)
    #expect(tornReadFlag.wasTorn == false, "a reader read a half-written file")
    #expect(filesPresent().filter { $0.hasPrefix(".") }.isEmpty)
}

/// Whether the write under test has finished, read from other threads.
private final class WriteInProgressFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var running = true

    func finish() {
        lock.lock()
        running = false
        lock.unlock()
    }

    var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return running
    }
}

/// Whether any reader thread has read a half-written file.
private final class TornReadFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var torn = false

    func markTorn() {
        lock.lock()
        torn = true
        lock.unlock()
    }

    var wasTorn: Bool {
        lock.lock()
        defer { lock.unlock() }
        return torn
    }
}
