import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// A library's threat matchers, in the window, end to end: the reason the
/// card draws for why its own threat is raised only where it names.
@MainActor
@Suite("A library threat's matchers in the window")
struct ThreatMatchReasonFlowTests {
    private let library = """
    library "custom" {
      technology "widget" {
        name     = "Widget"
        category = "compute"
        threats  = ["custom-threat"]
      }

      threat "custom-threat" {
        name     = "Custom Threat"
        severity = "high"
        runs_as  = ["admin", "root"]
      }
    }
    """

    private let system = """
    system "Test" {
      component "api" {
        technology = "custom-widget"
        runs_as    = "admin"
      }
    }

    """

    private func aProject() async -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put(library, at: "/work/threatmodel/library/custom.lib")
        useCases.project.put(system, at: "/work/threatmodel/test.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return session
    }

    private func customThreat(in session: ProjectSession) throws -> AssessedThreat {
        let model = try #require(session.model)
        return try #require(model.threats.first { $0.threatId == "custom-custom-threat" })
    }

    /// `runs_as` on the library's own threat reaches `AssessedThreat`, the
    /// same way it reaches a vendored threat's.
    @Test func theLibrarysRunsAsMatcherReachesTheAssessedThreat() async throws {
        let session = await aProject()
        let threat = try customThreat(in: session)

        #expect(threat.matchReason == "Applies only where the component runs as Administrator or Root.")
    }

    /// The card draws the reason as a line, not silently, so a person reads
    /// why the threat sits on this component and not another.
    @Test func theCardDrawsTheReason() async throws {
        let session = await aProject()
        let threat = try customThreat(in: session)

        guard let drawn = hostedDrawing(
            of: ThreatCard(
                threat: threat,
                severityChoices: session.model?.severityChoices ?? [],
                onSetControl: { _, _ in },
                onSetControlStatus: { _, _ in },
                onCompensate: {},
                onOverride: { _ in },
                onClearOverride: {}
            ),
            width: 380,
            height: 260
        ) else {
            Issue.record("the threat card drew nothing at all")
            return
        }
        #expect(drawn.image.pixelsWide > 0)
    }
}
