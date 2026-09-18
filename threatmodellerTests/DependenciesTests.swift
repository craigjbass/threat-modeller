import Foundation
import Testing
import ThreatModelKit
@testable import threatmodeller

/// The production root's layout listener.
///
/// `UseCaseFactory.layoutProgress` is optional because the protocol requires
/// an optional. This root always builds one, so the window always has
/// something to listen to while a model opens.
struct DependenciesTests {
    @Test func theProductionRootsLayoutProgressIsNeverNil() throws {
        #expect(try Dependencies().layoutProgress != nil)
    }

    @Test func layOutModelReportsToTheListenerOnTheRootsLayoutProgress() throws {
        let useCases = try Dependencies()
        let heard = Heard()
        useCases.layoutProgress?.listen { heard.receive($0) }

        _ = useCases.layOutModel().execute(
            LayOutModelRequest(source: ArchitectureSource(systemName: "Payments"))
        )

        #expect(heard.count() > 0)
    }
}

/// How many reports a listener heard. A layout report carries no identity
/// worth comparing here, so the test counts rather than inspects one.
private final class Heard: @unchecked Sendable {
    private let lock = NSLock()
    private var total = 0
    func receive(_ report: LayOutModelResponse) { lock.lock(); total += 1; lock.unlock() }
    func count() -> Int { lock.lock(); defer { lock.unlock() }; return total }
}
