import Foundation
import Testing
@testable import threatmodeller

@Suite("What build this is")
struct AboutVersionTests {
    @Test func readsTheVersionAndTheBuildFromTheBundle() {
        let version = AboutVersion([
            "CFBundleShortVersionString": "1.0.2",
            "CFBundleVersion": "412"
        ])

        #expect(version.described == "Version 1.0.2 (build 412)")
        #expect(version.releaseName == nil)
    }

    @Test func readsTheReleaseNameTheReleaseSet() {
        let version = AboutVersion([
            "CFBundleShortVersionString": "1.0.2",
            "CFBundleVersion": "412",
            "TMReleaseName": "v1.0.2-beta-dd164bf"
        ])

        #expect(version.releaseName == "v1.0.2-beta-dd164bf")
    }

    @Test func namesNoReleaseForABuildNobodyReleased() {
        // A build from Xcode substitutes nothing for TM_RELEASE_NAME, and the
        // key is left as an empty string rather than left out.
        let version = AboutVersion([
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
            "TMReleaseName": ""
        ])

        #expect(version.releaseName == nil)
        #expect(version.described == "Version 1.0 (build 1)")
    }

    @Test func standsUpToABundleThatSaysNothing() {
        let version = AboutVersion(nil)

        #expect(version.described == "Version 1.0 (build 1)")
        #expect(version.releaseName == nil)
    }

    @Test func readsThisBundle() {
        // The window reads the running bundle, so the keys have to be there.
        let version = AboutVersion.ofThisBundle

        #expect(version.version.isEmpty == false)
        #expect(version.build.isEmpty == false)
    }
}
