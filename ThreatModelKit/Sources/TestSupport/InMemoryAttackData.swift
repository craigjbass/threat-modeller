import Foundation
import ThreatModelKit

/// The ATT&CK data a test states, in memory.
public final class InMemoryAttackData: AttackDataGateway, @unchecked Sendable {
    private let lock = NSLock()
    private var filesByName: [String: String] = [:]
    private var modifiedByName: [String: Date] = [:]
    private var readsValue: [String] = []

    /// When this fake says a write happened. A test moves it by hand, so no
    /// test reads a real clock.
    public var now = Date(timeIntervalSince1970: 1_700_000_000)

    public let directory = "/attack"

    public init() {}

    /// Every file something read, in order. A test states that a project
    /// facing no ATT&CK group reads neither file.
    public var reads: [String] {
        lock.lock()
        defer { lock.unlock() }
        return readsValue
    }

    public func put(_ text: String, fileName: String) {
        lock.lock()
        defer { lock.unlock() }
        filesByName[fileName] = text
        modifiedByName[fileName] = now
    }

    public func read(fileName: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        readsValue.append(fileName)
        return filesByName[fileName]
    }

    public func write(_ text: String, fileName: String) throws {
        lock.lock()
        defer { lock.unlock() }
        filesByName[fileName] = text
        modifiedByName[fileName] = now
    }

    public func modified(fileName: String) -> Date? {
        lock.lock()
        defer { lock.unlock() }
        return modifiedByName[fileName]
    }
}

/// A downloader a test fills by hand, so nothing reaches a network.
public final class FakeAttackDownloader: AttackDownloading, @unchecked Sendable {
    private let lock = NSLock()
    private var bytesByAddress: [String: Data] = [:]
    private var faultByAddress: [String: AttackDownloadFault] = [:]
    private var downloadsValue: [String] = []
    private var gate: DispatchSemaphore?

    public init() {}

    /// Every address something asked for, in order. A test states that
    /// opening, drawing, compiling and reporting ask for none.
    public var downloads: [String] {
        lock.lock()
        defer { lock.unlock() }
        return downloadsValue
    }

    public func put(_ bytes: Data, at address: String) {
        lock.lock()
        defer { lock.unlock() }
        bytesByAddress[address] = bytes
    }

    public func refuse(_ fault: AttackDownloadFault, at address: String) {
        lock.lock()
        defer { lock.unlock() }
        faultByAddress[address] = fault
    }

    /// Holds every download until `release`, so a test reads the state of a
    /// synchronise while it runs.
    public func hold() {
        lock.lock()
        defer { lock.unlock() }
        gate = DispatchSemaphore(value: 0)
    }

    /// Lets a held download finish.
    public func release() {
        lock.lock()
        let held = gate
        gate = nil
        lock.unlock()
        held?.signal()
    }

    public func download(from address: String) throws -> Data {
        lock.lock()
        downloadsValue.append(address)
        let fault = faultByAddress[address]
        let bytes = bytesByAddress[address]
        let held = gate
        lock.unlock()

        held?.wait()
        if let fault { throw fault }
        guard let bytes else {
            throw AttackDownloadFault.cannotRead(reason: "curl: (22) The requested URL returned error: 404")
        }
        return bytes
    }
}
