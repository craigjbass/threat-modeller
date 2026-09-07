import Testing
@testable import ThreatModelKit

struct PackageBuildsTests {
    @Test func theCoreTargetIsImportable() {
        #expect(threatModelKitIsWired)
    }
}
