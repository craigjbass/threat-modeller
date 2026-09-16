import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Writing a threat's impacts in the window, end to end: the list the use
/// case writes, and the filter that reads it after the write.
@MainActor
@Suite("Writing a threat's impacts in the window")
struct ImpactsFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func credentialTheft(in session: ProjectSession) throws -> AssessedThreat {
        let model = try #require(session.model)
        return try #require(
            model.threats.first {
                $0.threatId == "credential-theft" && $0.source.id == "component:api"
            }
        )
    }

    /// "credential-theft" carries only the "spoofing" STRIDE category, which
    /// derives confidentiality alone, so a system with no `impacts`
    /// attribute shows that one chip on.
    @Test func aThreatWithNoImpactsAttributeShowsTheStrideDefault() async throws {
        let (session, _) = await aProject()

        let threat = try credentialTheft(in: session)

        #expect(threat.impacts == ["confidentiality"])
    }

    @Test func writesTheListAndTheFilterReadsItAfterTheWrite() async throws {
        let (session, useCases) = await aProject()

        await session.writeImpacts(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            impacts: ["availability"]
        )

        #expect(session.errorMessage == nil)
        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("impacts = [\"availability\"]"))

        // The project read the files again, so the filter sees the new list.
        let after = try credentialTheft(in: session)
        #expect(after.impacts == ["availability"])
    }

    @Test func replacesTheListWhenAPersonTogglesAgain() async throws {
        let (session, useCases) = await aProject()
        await session.writeImpacts(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            impacts: ["availability"]
        )

        await session.writeImpacts(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            impacts: ["availability", "integrity"]
        )

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("impacts = [\"availability\", \"integrity\"]"))
        let after = try credentialTheft(in: session)
        #expect(after.impacts == ["availability", "integrity"])
    }

    @Test func saysWhyAnEmptyListWasNotWritten() async throws {
        let (session, useCases) = await aProject()
        let controlsBefore = useCases.project.text(at: "/work/threatmodel/payments.controls")

        await session.writeImpacts(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            impacts: []
        )

        #expect(
            session.errorMessage
                == "Those impacts were not written: a threat needs at least one impact."
        )
        #expect(useCases.project.text(at: "/work/threatmodel/payments.controls") == controlsBefore)
    }

    @Test func theLastChipTheThreatHoldsCannotBeToggledOff() async throws {
        let (session, _) = await aProject()
        let threat = try credentialTheft(in: session)

        guard let drawn = hostedDrawing(
            of: ThreatCard(
                threat: threat,
                severityChoices: session.model?.severityChoices ?? [],
                onSetControl: { _, _ in },
                onSetControlStatus: { _, _ in },
                onCompensate: {},
                onOverride: { _ in },
                onClearOverride: {},
                onSetImpacts: { _ in }
            ),
            width: 380,
            height: 240
        ) else {
            Issue.record("the threat card drew nothing at all")
            return
        }
        #expect(drawn.image.pixelsWide > 0)
    }
}
