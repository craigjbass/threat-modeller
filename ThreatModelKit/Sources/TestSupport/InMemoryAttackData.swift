import Foundation
import ThreatModelKit

/// The ATT&CK data a test states, in memory.
public final class InMemoryAttackData: AttackDataGateway, @unchecked Sendable {
    private let lock = NSLock()
    private var filesByName: [String: String] = [:]
    private var readsValue: [String] = []

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
    }
}

/// A downloader a test fills by hand, so nothing reaches a network.
public final class FakeAttackDownloader: AttackDownloading, @unchecked Sendable {
    private let lock = NSLock()
    private var bytesByAddress: [String: Data] = [:]
    private var faultByAddress: [String: AttackDownloadFault] = [:]
    private var downloadsValue: [String] = []

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

    public func download(from address: String) throws -> Data {
        lock.lock()
        downloadsValue.append(address)
        let fault = faultByAddress[address]
        let bytes = bytesByAddress[address]
        lock.unlock()

        if let fault { throw fault }
        guard let bytes else {
            throw AttackDownloadFault.cannotRead(reason: "curl: (22) The requested URL returned error: 404")
        }
        return bytes
    }
}
