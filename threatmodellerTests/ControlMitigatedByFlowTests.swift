import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Saying in the window that a `mitigates` edge implements a control, end to
/// end: the card offers the edges that answer the threat, picking one records
/// the control, a save writes `mitigated_by`, and a reopen reads it back.
@MainActor
@Suite("Saying in the window what implements a control")
struct ControlMitigatedByFlowTests {
    private let payments = """
    system "Payments" {
      component "guard" {
        technology = "aws-waf"
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      mitigates guard -> api {
        threats         = ["credential-theft"]
        reduces_risk_by = 80
      }
    }

    """

    private let control = "Enforce IMDSv2 to block SSRF-based credential theft"
    private let controlsPath = "/work/threatmodel/payments.controls"

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

    private func theThreat(of session: ProjectSession) throws -> AssessedThreat {
        let model = try #require(session.model)
        return try #require(
            model.threats.first {
                $0.threatId == "credential-theft" && $0.source.id == "component:api"
            }
        )
    }

    private func theControl(of session: ProjectSession) throws -> AssessedControl {
        try #require(theThreat(of: session).controls.first { $0.description == control })
    }

    @Test func offersTheEdgesThatAnswerTheThreatOnThisElement() async throws {
        let (session, _) = await aProject()
        let threat = try theThreat(of: session)

        #expect(threat.mitigatesEdgeChoices.map(\.id) == ["guard->api"])
        #expect(threat.mitigatesEdgeChoices.map(\.label) == ["WAF (80%)"])
        #expect(ThreatCard.reducedBy(threat) == "WAF (80%)")
    }

    @Test func pickingAnEdgeRecordsTheControlAndWritesTheFile() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setControlMitigatedBy(key: try theControl(of: session).key, edgeId: "guard->api")
        #expect(model.errorMessage == nil)

        let shown = try theControl(of: session)
        #expect(shown.mitigatedByEdgeId == "guard->api")
        #expect(shown.isImplemented)

        await session.save()

        let written = try #require(useCases.project.text(at: controlsPath))
        #expect(written.contains("mitigated_by = \"guard->api\""))
    }

    @Test func aReopenKeepsWhatImplementsTheControl() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        model.setControlMitigatedBy(key: try theControl(of: session).key, edgeId: "guard->api")
        await session.save()

        let reopened = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await reopened.open(root: "/work")

        #expect(try theControl(of: reopened).mitigatedByEdgeId == "guard->api")
    }

    @Test func pickingNobodyTakesTheMappingOff() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        model.setControlMitigatedBy(key: try theControl(of: session).key, edgeId: "guard->api")

        model.setControlMitigatedBy(key: try theControl(of: session).key, edgeId: nil)
        await session.save()

        #expect(try theControl(of: session).mitigatedByEdgeId == nil)
        let written = try #require(useCases.project.text(at: controlsPath))
        #expect(written.contains("mitigated_by") == false)
    }

    @Test func takesTheThreatOutOfTheUnansweredFilter() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        var filter = ThreatFilter()
        filter.answered = .unanswered

        #expect(filter.narrow(model.threats).contains { $0.threatId == "credential-theft" })

        model.setControlMitigatedBy(key: try theControl(of: session).key, edgeId: "guard->api")

        let shown = try #require(session.model)
        #expect(
            filter.narrow(shown.threats).contains {
                $0.threatId == "credential-theft" && $0.source.id == "component:api"
            } == false
        )
    }

    @Test func statesWhyAnAssumedEdgeImplementsNothing() async throws {
        let useCases = TestDependencies()
        useCases.project.put(
            payments.replacingOccurrences(
                of: "reduces_risk_by = 80",
                with: "reduces_risk_by = 80\n    status          = \"assumed\""
            ),
            at: "/work/threatmodel/payments.arch"
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        let model = try #require(session.model)

        model.setControlMitigatedBy(key: try theControl(of: session).key, edgeId: "guard->api")

        #expect(
            model.errorMessage
                == "That mitigates edge is assumed, so it implements no control yet."
        )
        #expect(try theControl(of: session).mitigatedByEdgeId == nil)
    }
}
