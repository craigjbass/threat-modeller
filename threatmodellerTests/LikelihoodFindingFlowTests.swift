import AppKit
import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Writing a likelihood finding in the window, end to end: the block the use
/// case writes, the score that moves with it, and the finding that survives
/// the project closing and reopening.
@MainActor
@Suite("Writing a likelihood finding in the window")
struct LikelihoodFindingFlowTests {
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

    @Test func writesTheFindingAndTheThreatRescoresWithIt() async throws {
        let (session, useCases) = await aProject()
        let before = try credentialTheft(in: session)

        await session.writeLikelihoodFinding(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            label: "no campaign has used this against our stack",
            tier: "research",
            prior: nil,
            rationale: "No public reporting names this technique against this platform.",
            sources: ["https://example.com/threat-report"]
        )

        #expect(session.errorMessage == nil)
        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("likelihood \"no campaign has used this against our stack\" {"))
        #expect(written.contains("tier      = \"research\""))

        // The project read the files again, so the card states the finding
        // and the score moved with it.
        let after = try credentialTheft(in: session)
        #expect(after.riskScore < before.riskScore)
        #expect(after.likelihoodId == "research")
        #expect(
            after.likelihoodRationale
                == "No public reporting names this technique against this platform."
        )
        #expect(after.likelihoodSources == ["https://example.com/threat-report"])
    }

    /// A finding a person wrote from the window has to be there after the
    /// project closes and reopens, not only after the write that wrote it.
    @Test func theFindingSurvivesTheProjectClosingAndReopening() async throws {
        let (session, useCases) = await aProject()

        await session.writeLikelihoodFinding(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            label: "no campaign has used this against our stack",
            tier: "research",
            prior: nil,
            rationale: "No public reporting names this technique against this platform.",
            sources: []
        )
        let scoredAfterWriting = try credentialTheft(in: session).riskScore

        // A fresh session over the same files, standing in for the project
        // closing and a person opening it again.
        let reopened = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await reopened.open(root: "/work")

        let reread = try credentialTheft(in: reopened)
        #expect(reread.likelihoodId == "research")
        #expect(
            reread.likelihoodRationale
                == "No public reporting names this technique against this platform."
        )
        #expect(reread.riskScore == scoredAfterWriting)
    }

    @Test func replacesTheFindingWhenAPersonEditsIt() async throws {
        let (session, useCases) = await aProject()
        await session.writeLikelihoodFinding(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            label: "no campaign has used this against our stack",
            tier: "commodity",
            prior: nil,
            rationale: "Nothing found yet.",
            sources: []
        )

        await session.writeLikelihoodFinding(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            label: "a researcher published a proof of concept",
            tier: "research",
            prior: nil,
            rationale: "A conference talk showed the technique with no known exploitation.",
            sources: []
        )

        let written = try #require(useCases.project.text(at: "/work/threatmodel/payments.controls"))
        #expect(written.contains("likelihood \"a researcher published a proof of concept\" {"))
        #expect(written.contains("likelihood \"no campaign has used this against our stack\" {") == false)
        let after = try credentialTheft(in: session)
        #expect(after.likelihoodId == "research")
    }

    @Test func saysWhyAFindingWithNoRationaleWasNotWritten() async throws {
        let (session, useCases) = await aProject()
        let controlsBefore = useCases.project.text(at: "/work/threatmodel/payments.controls")

        await session.writeLikelihoodFinding(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            label: "no campaign has used this against our stack",
            tier: "research",
            prior: nil,
            rationale: "  ",
            sources: []
        )

        #expect(
            session.errorMessage
                == "That finding was not written: a likelihood finding needs a rationale."
        )
        #expect(useCases.project.text(at: "/work/threatmodel/payments.controls") == controlsBefore)
    }

    @Test func drawsTheSheetThatWritesTheFinding() async throws {
        let (session, _) = await aProject()
        let threat = try credentialTheft(in: session)

        guard let drawn = hostedDrawing(
            of: LikelihoodSheet(
                threat: threat,
                session: session.model ?? LayoutPreview.session(),
                project: session
            ),
            width: 460,
            height: 560
        ) else {
            Issue.record("the likelihood sheet drew nothing at all")
            return
        }
        #expect(drawn.image.pixelsWide > 0)
    }

    // MARK: the sheet the Threats stage opens with How often…

    /// True when the picture holds more than one pixel value, the mark of a
    /// view that drew real content rather than one blank rectangle.
    private func hasContent(_ image: NSBitmapImageRep) -> Bool {
        var seen: Set<String> = []
        let across = stride(from: 4, to: image.pixelsWide - 4, by: max(1, image.pixelsWide / 40))
        let down = stride(from: 4, to: image.pixelsHigh - 4, by: max(1, image.pixelsHigh / 40))
        for x in across {
            for y in down {
                guard let colour = image.colorAt(x: x, y: y) else { continue }
                seen.insert(
                    String(
                        format: "%.2f,%.2f,%.2f,%.2f",
                        colour.redComponent,
                        colour.greenComponent,
                        colour.blueComponent,
                        colour.alphaComponent
                    )
                )
                if seen.count > 1 { return true }
            }
        }
        return false
    }

    /// Every sampled pixel of a drawn image, so one picture is compared with
    /// another. A control that draws differently when disabled changes some
    /// of these.
    private func pixels(of image: NSBitmapImageRep) -> [String] {
        var read: [String] = []
        for x in stride(from: 0, to: image.pixelsWide, by: 2) {
            for y in stride(from: 0, to: image.pixelsHigh, by: 2) {
                guard let colour = image.colorAt(x: x, y: y) else { continue }
                read.append(
                    String(format: "%.2f,%.2f,%.2f", colour.redComponent, colour.greenComponent, colour.blueComponent)
                )
            }
        }
        return read
    }

    /// The Threats stage builds `ThreatSidebar(session:, focus: .likelihood,
    /// project:)`. With a project, the sidebar draws real content and the
    /// sheet it opens for "How often…" is the label field, the tier picker
    /// and the Save button, not a blank sheet.
    @Test func drawsTheThreatsStageSidebarAndItsLikelihoodSheetWithAProject() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let threat = try credentialTheft(in: session)

        let sidebar = try #require(
            hostedDrawing(
                of: ThreatSidebar(session: model, focus: .likelihood, project: session),
                width: 420,
                height: 700
            )
        )
        #expect(hasContent(sidebar.image), "the Threats stage sidebar drew a blank rectangle")

        let sheet = try #require(
            hostedDrawing(
                of: LikelihoodSheet(threat: threat, session: model, project: session),
                width: 460,
                height: 560
            )
        )
        #expect(hasContent(sheet.image), "the likelihood sheet drew a blank rectangle")
    }

    /// The Controls stage builds `ThreatSidebar(session:, focus: .controls,
    /// project:)`, the pairing that already worked before this fix. The same
    /// likelihood sheet still draws real content from that pairing, so the
    /// fix for the Threats stage changed nothing here.
    @Test func drawsTheControlsStageSidebarAndItsLikelihoodSheetWithAProject() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)
        let threat = try credentialTheft(in: session)

        let sidebar = try #require(
            hostedDrawing(
                of: ThreatSidebar(session: model, focus: .controls, project: session),
                width: 420,
                height: 700
            )
        )
        #expect(hasContent(sidebar.image), "the Controls stage sidebar drew a blank rectangle")

        let sheet = try #require(
            hostedDrawing(
                of: LikelihoodSheet(threat: threat, session: model, project: session),
                width: 460,
                height: 560
            )
        )
        #expect(hasContent(sheet.image), "the likelihood sheet drew a blank rectangle")
    }

    /// A window with no project reaches the empty-project case: the sheet
    /// shows the one line saying the finding needs an open project, and the
    /// card's How often… button is disabled with the same reason as a
    /// tooltip, instead of opening an empty sheet.
    @Test func showsTheOneLineAndDisablesTheButtonWithNoProject() throws {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        let threat = try #require(session.threats.first)

        let sidebar = try #require(
            hostedDrawing(
                of: ThreatSidebar(session: session, focus: .likelihood, project: nil),
                width: 420,
                height: 700
            )
        )
        #expect(hasContent(sidebar.image), "the sidebar with no project drew a blank rectangle")

        let needsProjectSheet = try #require(
            hostedDrawing(of: NeedsProjectSheet(), width: 320, height: 200)
        )
        #expect(hasContent(needsProjectSheet.image), "the empty-project sheet drew a blank rectangle")

        let disabledCard = try #require(
            hostedDrawing(
                of: ThreatCard(
                    threat: threat,
                    focus: .likelihood,
                    severityChoices: [],
                    onSetControl: { _, _ in },
                    onSetControlStatus: { _, _ in },
                    onCompensate: {},
                    onOverride: { _ in },
                    onClearOverride: {}
                ),
                width: 420,
                height: 260
            )
        )
        let enabledCard = try #require(
            hostedDrawing(
                of: ThreatCard(
                    threat: threat,
                    focus: .likelihood,
                    severityChoices: [],
                    onSetControl: { _, _ in },
                    onSetControlStatus: { _, _ in },
                    onCompensate: {},
                    onLikelihood: {},
                    onOverride: { _ in },
                    onClearOverride: {}
                ),
                width: 420,
                height: 260
            )
        )
        #expect(
            pixels(of: disabledCard.image) != pixels(of: enabledCard.image),
            "the card drew the same picture whether the button was disabled or not"
        )
    }
}
