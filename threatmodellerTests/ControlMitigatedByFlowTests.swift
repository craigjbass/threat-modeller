import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Saying in the window that a `mitigates` edge implements a control, end to
/// end: the card offers the edges that answer the threat, naming one records
/// the control, a save writes the `mitigated_by` block, and a reopen reads it
/// back.
@MainActor
@Suite("Saying in the window what implements a control")
struct ControlMitigatedByFlowTests {
    private let payments = """
    system "Payments" {
      component "guard" {
        technology = "aws-waf"
      }

      component "vault" {
        technology = "aws-waf"
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      mitigates guard -> api {
        threats = ["credential-theft"]
      }

      mitigates vault -> api {
        threats = ["credential-theft"]
      }
    }

    """

    private let control = "Enforce IMDSv2 to block SSRF-based credential theft"
    private let controlsPath = "/work/threatmodel/payments.controls"

    private func aProject(_ architecture: String? = nil) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(architecture ?? payments, at: "/work/threatmodel/payments.arch")
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

        #expect(threat.mitigatesEdgeChoices.map(\.id).sorted() == ["guard->api", "vault->api"])
        #expect(threat.mitigatesEdgeChoices.map(\.label) == ["WAF", "WAF"])
    }

    @Test func namingAnEdgeRecordsTheControlAndWritesTheFile() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        model.setControlMitigatedBy(
            key: try theControl(of: session).key,
            edgeId: "guard->api",
            reducesRiskBy: 80
        )
        #expect(model.errorMessage == nil)

        let shown = try theControl(of: session)
        #expect(shown.mitigations == [ControlMitigation(edgeId: "guard->api", reducesRiskBy: 80)])
        #expect(shown.isImplemented)

        await session.save()

        let written = try #require(useCases.project.text(at: controlsPath))
        #expect(written.contains("mitigated_by \"guard->api\" {"))
        #expect(written.contains("reduces_risk_by = 80"))
    }

    @Test func namesTwoEdgesOnOneControl() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let key = try theControl(of: session).key

        model.setControlMitigatedBy(key: key, edgeId: "guard->api", reducesRiskBy: 80)
        model.setControlMitigatedBy(key: key, edgeId: "vault->api", reducesRiskBy: 40)
        await session.save()

        let written = try #require(useCases.project.text(at: controlsPath))
        #expect(written.contains("mitigated_by \"guard->api\" {"))
        #expect(written.contains("mitigated_by \"vault->api\" {"))
        #expect(try theControl(of: session).mitigations.count == 2)
    }

    @Test func aReopenKeepsWhatImplementsTheControl() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        model.setControlMitigatedBy(
            key: try theControl(of: session).key,
            edgeId: "guard->api",
            reducesRiskBy: 80
        )
        await session.save()

        let reopened = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await reopened.open(root: "/work")

        #expect(
            try theControl(of: reopened).mitigations
                == [ControlMitigation(edgeId: "guard->api", reducesRiskBy: 80)]
        )
    }

    @Test func removingTheLastMappingTakesItOutOfTheFile() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let key = try theControl(of: session).key
        model.setControlMitigatedBy(key: key, edgeId: "guard->api", reducesRiskBy: 80)

        model.setControlMitigatedBy(key: key, edgeId: "guard->api", reducesRiskBy: nil)
        await session.save()

        #expect(try theControl(of: session).mitigations.isEmpty)
        let written = try #require(useCases.project.text(at: controlsPath))
        #expect(written.contains("mitigated_by") == false)
    }

    @Test func takesTheThreatOutOfTheUnansweredFilter() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        var filter = ThreatFilter()
        filter.answered = .unanswered

        #expect(filter.narrow(model.threats).contains { $0.threatId == "credential-theft" })

        model.setControlMitigatedBy(
            key: try theControl(of: session).key,
            edgeId: "guard->api",
            reducesRiskBy: 80
        )

        let shown = try #require(session.model)
        #expect(
            filter.narrow(shown.threats).contains {
                $0.threatId == "credential-theft" && $0.source.id == "component:api"
            } == false
        )
    }

    @Test func leavesAControlOpenWhileTheEdgeItNamesIsProposed() async throws {
        let (session, _) = await aProject(
            payments.replacingOccurrences(
                of: "mitigates guard -> api {\n    threats = [\"credential-theft\"]",
                with: "mitigates guard -> api {\n    threats = [\"credential-theft\"]\n    status  = \"proposed\""
            )
        )
        let model = try #require(session.model)

        model.setControlMitigatedBy(
            key: try theControl(of: session).key,
            edgeId: "guard->api",
            reducesRiskBy: 80
        )

        #expect(model.errorMessage == nil)
        let shown = try theControl(of: session)
        #expect(shown.isImplemented == false)
        #expect(shown.mitigations.isEmpty == false)
    }

    @Test func statesWhyAReductionOutsideItsRangeIsRefused() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        model.setControlMitigatedBy(
            key: try theControl(of: session).key,
            edgeId: "guard->api",
            reducesRiskBy: 101
        )

        #expect(model.errorMessage == "How much an edge takes off runs from 0 to 100.")
        #expect(try theControl(of: session).mitigations.isEmpty)
    }
}
