import Foundation
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// What the window says when a system's file names another catalogue tag.
///
/// The threats, the controls and the scores may have moved under the file, so
/// the window states both tags and offers the two things a person can do.
@MainActor
@Suite("A system written against another catalogue tag")
struct CatalogueDriftTests {
    private let older = """
    system "Payments" {
      catalogue = "v0.0.1"

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private let current = """
    system "Payments" {
      catalogue = "v0.0.0"

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject(
        _ text: String,
        defaults: UserDefaults? = nil
    ) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(text, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: defaults ?? aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    @Test func namesBothTagsWhenTheyDiffer() async throws {
        let (session, _) = await aProject(older)

        let drift = try #require(session.catalogueDrift)
        #expect(drift.stated == "v0.0.1")
        #expect(drift.inUse == "v0.0.0")
        #expect(drift.fileName == "payments.arch")
        #expect(
            drift.says
                == "payments.arch was written against catalogue v0.0.1, "
                    + "and the catalogue in use is v0.0.0."
        )
    }

    @Test func saysNothingWhenTheTagsMatch() async {
        let (session, _) = await aProject(current)

        #expect(session.catalogueDrift == nil)
    }

    @Test func saysNothingWhenTheFileStatesNoTag() async {
        let (session, _) = await aProject("""
        system "Payments" {
          component "api" {
            technology = "aws-ec2"
          }
        }

        """)

        #expect(session.catalogueDrift == nil)
    }

    @Test func takesTheTagInUseAndRewritesTheFile() async throws {
        let (session, useCases) = await aProject(older)
        #expect(session.catalogueDrift != nil)

        session.takeTheCatalogueInUse()
        await session.settle()

        let written = try #require(try useCases.project.read(path: "/work/threatmodel/payments.arch"))
        #expect(written.contains("catalogue = \"v0.0.0\""))
        #expect(written.contains("v0.0.1") == false)
        #expect(session.catalogueDrift == nil)
    }

    @Test func keepsTheStatedTagAndLeavesTheFileAlone() async throws {
        let (session, useCases) = await aProject(older)

        session.keepTheStatedCatalogue()

        #expect(session.catalogueDrift == nil)
        let written = try #require(try useCases.project.read(path: "/work/threatmodel/payments.arch"))
        #expect(written.contains("catalogue = \"v0.0.1\""))
    }

    /// A dismissal belongs to the file and the pair of tags, not to the
    /// window, so opening the project again does not ask twice.
    @Test func remembersTheDismissalForThatFileAndThatPairOfTags() async {
        let defaults = aTestDefaults()
        let (session, _) = await aProject(older, defaults: defaults)
        session.keepTheStatedCatalogue()

        let (reopened, _) = await aProject(older, defaults: defaults)

        #expect(reopened.catalogueDrift == nil)
    }

    @Test func asksAgainForAnotherPairOfTags() async throws {
        let defaults = aTestDefaults()
        let (session, _) = await aProject(older, defaults: defaults)
        session.keepTheStatedCatalogue()

        let (reopened, _) = await aProject("""
        system "Payments" {
          catalogue = "v0.0.2"

          component "api" {
            technology = "aws-ec2"
          }
        }

        """, defaults: defaults)

        #expect(try #require(reopened.catalogueDrift).stated == "v0.0.2")
    }
}
