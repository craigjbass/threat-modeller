import Foundation
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

@MainActor
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

    // MARK: the libraries the window states

    @Test func statesEveryLibraryTheProjectReads() async throws {
        let useCases = TestDependencies()
        useCases.project.put(
            "system \"Payments\" { }",
            at: "/work/threatmodel/payments.arch"
        )
        useCases.project.put(
            "library \"acme\" { name = \"Acme Platform\" }",
            at: "/work/threatmodel/library/acme.lib"
        )
        useCases.project.put(
            """
            {
              "version" : 1,
              "libraries" : {
                "acme" : {
                  "repository" : "/elements",
                  "tag" : "v1.0.0",
                  "files" : { "acme.lib" : "0" }
                }
              }
            }
            """,
            at: "/work/threatmodel/library/library.lock.json"
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")

        let libraries = session.libraries

        #expect(libraries.map(\.label) == ["acme"])
        #expect(libraries.first?.repository == "/elements")
        #expect(libraries.first?.tag == "v1.0.0")
    }

    @Test func statesNoneForAProjectThatReadsNoLibrary() async {
        let useCases = TestDependencies()
        useCases.project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")

        #expect(session.libraries.isEmpty)
    }

    /// The window states what the Libraries sheet states: both read
    /// `ListLibraries`.
    @Test func theWindowAndTheSheetStateTheSame() async throws {
        let useCases = TestDependencies()
        useCases.project.put("system \"Payments\" { }", at: "/work/threatmodel/payments.arch")
        useCases.project.put(
            "library \"acme\" { name = \"Acme Platform\" }",
            at: "/work/threatmodel/library/acme.lib"
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        let sheet = LibrarySession(useCases: useCases, root: "/work", onChange: {})
        sheet.reload()

        #expect(session.libraries.map(\.label) == sheet.libraries.map(\.label))
        #expect(session.libraries.map(\.tag) == sheet.libraries.map(\.tag))
    }
}
