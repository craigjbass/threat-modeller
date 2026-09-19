import AppKit
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The Report stage: the report read in the window, with no file written.
///
/// The design is `docs/superpowers/specs/2026-09-16-report-stage-design.md`.
@MainActor
struct ReportStageTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
      component "store" {
        technology = "aws-rds"
        data       = "confidential"
      }
      flow api -> store
    }

    """

    private func aProject(
        policy: String? = nil,
        template: (text: String, path: String)? = nil
    ) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        if let policy { useCases.project.put(policy, at: "/work/threatmodel/policy.hcl") }
        if let template { useCases.project.put(template.text, at: template.path) }
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    /// The page the stage draws for the open project.
    private func page(of project: ProjectSession) throws -> ReportStagePage {
        try #require(project.model).reportStagePage()
    }

    private func section(
        _ slot: ReportTemplate.Slot,
        of page: ReportStagePage
    ) throws -> ReportStageSection {
        try #require(
            page.sections.first { $0.slot == slot },
            "the page holds no \(slot.rawValue) section"
        )
    }

    /// Every paragraph of a section, as text.
    private func paragraphs(of section: ReportStageSection) -> [String] {
        section.blocks.compactMap { block in
            if case .paragraph(let text) = block { return text }
            return nil
        }
    }

    /// Every numbered list of a section, as its lines.
    private func numbered(of section: ReportStageSection) -> [[String]] {
        section.blocks.compactMap { block in
            if case .numbered(let bullets) = block { return bullets.map(\.text) }
            return nil
        }
    }

    // MARK: the stage is the fifth stage

    /// The stages, in the order the panel lists them. Report sits after
    /// Controls, because reading the report is the last thing a person does.
    @Test func listsTheFiveStagesInOrder() {
        #expect(
            WorkStage.allCases == [.architecture, .attackTrees, .threats, .controls, .report]
        )
        #expect(WorkStage.report.label == "Report")
    }

    // MARK: what the stage draws

    /// The executive summary the stage draws states the numbers
    /// `BuildThreatModelReport` gives for the same model.
    @Test func drawsTheExecutiveSummaryNumbersTheReportGives() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)
        let summary = model.builtReport().executiveSummary

        let section = try section(.executiveSummary, of: try page(of: project))
        let said = paragraphs(of: section)

        #expect(section.title == "Executive summary")
        #expect(said.contains(summary.verdict))
        #expect(
            said.contains(
                "\(summary.unansweredCount) of \(summary.totalThreats) threats hold"
                    + " no answered control and no compensating control."
            )
        )
        #expect(summary.totalThreats > 0, "the model raised no threat to report")
    }

    /// The stage states how many known exploited CVEs the model holds, the
    /// same count the report states.
    @Test func statesHowManyKnownExploitedCvesTheModelHolds() async throws {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
                version    = "1.24.0"
                cves       = ["CVE-2023-44487"]
              }
              component "store" {
                technology = "aws-rds"
                data       = "confidential"
              }
              flow api -> store
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        useCases.project.put(
            VulnerabilityLock(
                cves: [
                    "CVE-2023-44487": KnownVulnerability(
                        id: "CVE-2023-44487", cvss: 7.5, epss: 0.94, isKnownExploited: true
                    )
                ],
                epssDate: "2026-09-15",
                kevCatalogueVersion: "2026.09.15"
            ).text,
            at: "/work/threatmodel/\(VulnerabilityLock.fileName)"
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")

        let model = try #require(session.model)
        let section = try section(.executiveSummary, of: model.reportStagePage())

        #expect(model.builtReport().executiveSummary.knownExploitedCount == 1)
        #expect(
            paragraphs(of: section).contains(
                "This model holds 1 known exploited CVE, listed under Known vulnerabilities."
            )
        )
    }

    /// Every note under a top risk in the stage is the reason the report
    /// states for that threat.
    @Test func statesTheSameReasonUnderATopRiskAsTheReport() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)
        let report = model.builtReport()

        let section = try section(.executiveSummary, of: try page(of: project))
        let bullets = try #require(
            section.blocks.compactMap { block -> [ReportBullet]? in
                if case .numbered(let bullets) = block { return bullets }
                return nil
            }.first
        )

        #expect(bullets.isEmpty == false)
        for (bullet, threat) in zip(bullets, report.executiveSummary.topRisks) {
            #expect(
                bullet.notes == ReportExecutiveSummary.reasons(
                    for: threat,
                    components: report.components,
                    connections: report.connections,
                    zones: report.zones,
                    withNoAction: report.executiveSummary.topRisksWithNoAction
                )
            )
        }
    }

    /// The three worst threats the report names are the three the stage lists
    /// first, with the same scores.
    @Test func listsTheTopRisksTheReportNames() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)
        let summary = model.builtReport().executiveSummary

        let section = try section(.executiveSummary, of: try page(of: project))
        let listed = try #require(numbered(of: section).first)

        #expect(listed.count == summary.topRisks.count)
        for (line, threat) in zip(listed, summary.topRisks) {
            #expect(line.contains(threat.name))
            #expect(line.contains("(\(threat.riskScore) of \(ReportMethodology.highestScore))"))
        }
    }

    /// An answer given on the Controls stage changes the stage's top actions
    /// on the next draw, and the window writes no report file to show it.
    @Test func aControlStatusChangesTheTopActionsWithNoFileWritten() async throws {
        let (project, useCases) = await aProject()
        await project.writeRecommendation(
            threatId: "credential-theft",
            sourceKind: "component",
            sourceId: "api",
            replacing: nil,
            text: "Enforce IMDSv2 on every instance",
            note: nil,
            sources: []
        )
        let model = try #require(project.model)

        let before = try numbered(of: section(.executiveSummary, of: try page(of: project)))
        let threat = try #require(
            model.threats.first {
                $0.threatId == "credential-theft" && $0.source.id == "component:api"
            }
        )
        for control in threat.controls {
            model.setControlStatus(key: control.key, statusId: "implemented")
        }

        let after = try numbered(of: section(.executiveSummary, of: try page(of: project)))

        #expect(before != after, "the top actions did not change")
        #expect(project.reportPath == nil, "the stage wrote a report")
        #expect(
            useCases.project.text(at: "/work/threatmodel/payments.md") == nil,
            "the stage wrote a report file"
        )
    }

    /// A template that names one section gives a stage of one section, so a
    /// reader sees on the stage what the file will hold.
    @Test func leavesOutASectionTheTemplateLeavesOut() async throws {
        let (project, _) = await aProject(
            policy: "policy {\n  template = \"board.md\"\n}\n",
            template: (
                text: "# The board's report\n\n{{executive_summary}}\n",
                path: "/work/board.md"
            )
        )

        let page = try page(of: project)

        #expect(page.sections.map(\.slot) == [.executiveSummary])
        #expect(page.templatePath == "/work/board.md")
        #expect(page.fault.isEmpty)
    }

    /// The shipped shape names every section, so a project with no template
    /// draws more than one.
    @Test func drawsEverySectionTheShippedShapeNames() async throws {
        let page = try page(of: await aProject().0)

        #expect(page.templatePath == nil)
        #expect(page.sections.count > 1)
        #expect(page.sections.contains { $0.slot == .executiveSummary })
        #expect(page.sections.contains { $0.slot == .threatRegister })
    }

    /// A template the policy names and the project does not hold stops the
    /// report, so the stage states the fault and draws no section.
    @Test func statesTheFaultWhenTheTemplateIsNotThere() async throws {
        let (project, _) = await aProject(policy: "policy {\n  template = \"board.md\"\n}\n")

        let page = try page(of: project)

        #expect(page.sections.isEmpty)
        #expect(page.fault == ["There is no template at /work/board.md."])
    }

    /// A diagram section draws the diagram, under the label the team gave it.
    /// The stage draws mermaid, so the text is not what a reader reads.
    @Test func drawsTheDiagramBlock() async throws {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }
              diagram "Login" {
                kind = "mermaid"
                text = "graph TD; a-->b;"
              }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        let project = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await project.open(root: "/work")

        let section = try section(.diagrams, of: try page(of: project))

        #expect(section.title == "Diagrams")
        #expect(section.blocks.contains(.subheading("Login")))
        #expect(
            section.blocks.contains { block in
                if case .picture = block { return true }
                return false
            }
        )
    }

    /// A known exploited CVE raises a threat's tier to Commodity, which is
    /// the tier every threat already carries by default, so the Likelihood
    /// line must print by the CVE's reason, not by the tier changing.
    /// `MarkdownThreatStanza` already reads this reason; the stage reads the
    /// same one.
    @Test func showsTheLikelihoodLineForAThreatAKnownExploitedCveSets() async throws {
        let architecture = """
        system "Payments" {
          component "api" {
            technology = "aws-ec2"
            data       = "confidential"
            cves       = ["CVE-2023-44487"]
          }
        }

        """
        let useCases = TestDependencies()
        useCases.project.put(architecture, at: "/work/threatmodel/payments.arch")
        let lock = VulnerabilityLock(
            cves: [
                "CVE-2023-44487": KnownVulnerability(
                    id: "CVE-2023-44487", cvss: 7.5, epss: 0.94, isKnownExploited: true
                )
            ],
            epssDate: "2026-09-15",
            kevCatalogueVersion: "2026.09.15"
        )
        useCases.project.put(lock.text, at: "/work/threatmodel/\(VulnerabilityLock.fileName)")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")

        let registered = try section(.threatRegister, of: try page(of: session))
        let bullets = registered.blocks.flatMap { block -> [ReportBullet] in
            if case .bullets(let items) = block { return items }
            return []
        }

        #expect(bullets.contains { $0.text.contains("set by CVE-2023-44487, known exploited") })
    }

    /// The window's tree reads the same ordered chain `MarkdownAttackTrees`
    /// writes to the file, so a person who never generates a report still
    /// sees which step comes first.
    @Test func showsTheTreesOrderedChainTheMarkdownWrites() async throws {
        let useCases = TestDependencies()
        useCases.project.put(payments, at: "/work/threatmodel/payments.arch")
        useCases.project.put(
            """
            attack_trees for "Payments" {
              tree "phishing" {
                goal "misconfiguration" on component "api"

                then {
                  step "credential-theft" on component "api"
                  step "misconfiguration" on component "api"
                }
              }
            }

            """,
            at: "/work/threatmodel/payments.attacktree"
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        let model = try #require(session.model)
        let report = model.builtReport()
        let markdown = MarkdownAttackTrees.lines(report.attackTrees, routes: report.attackPathCount)
        let chainLine = try #require(markdown.first { $0.hasPrefix("1. ") })

        let treeSection = try section(.attackTrees, of: try page(of: session))
        let numbered = treeSection.blocks.compactMap { block -> [ReportBullet]? in
            if case .numbered(let bullets) = block { return bullets }
            return nil
        }
        let firstChain = try #require(numbered.first)

        #expect(treeSection.blocks.contains(.lead("The chain, in order:")))
        #expect(firstChain.first?.text == String(chainLine.dropFirst(3)))
    }

    // MARK: reaching the stage

    /// The View menu's Report item runs `showStage`, the way the other four
    /// stage items do, and Cmd+5 is the key on it.
    @Test func theStageKeyReachesTheStage() async throws {
        var stage = WorkStage.architecture
        let canvas = CanvasState()
        canvas.showStage = { stage = $0 }

        canvas.showStage?(.report)

        #expect(stage == .report)
    }

    /// The panel's popup lists every stage and writes the one a person picks.
    @Test func thePanelReachesTheStage() async throws {
        let (project, _) = await aProject()
        let reached = Reached()
        let binding = Binding(get: { reached.stage }, set: { reached.stage = $0 })
        let popUp = try #require(
            stagePopUp(
                of: WorkflowPanel(session: project, stage: binding, columnWidth: 900)
            ),
            "the panel draws no stage popup"
        )

        #expect(popUp.itemTitles == WorkStage.allCases.map(\.label))

        let menu = try #require(popUp.menu)
        let item = try #require(menu.items.first { $0.title == WorkStage.report.label })
        menu.performActionForItem(at: menu.index(of: item))

        #expect(reached.stage == .report)
    }

    /// The stage a binding writes, so a test reads back what the popup chose.
    @MainActor
    private final class Reached {
        var stage = WorkStage.architecture
    }

    /// The panel's stage popup, laid out in a window.
    private func stagePopUp(of view: some View) -> NSPopUpButton? {
        let hosting = NSHostingView(rootView: view)
        hosting.frame = NSRect(x: 0, y: 0, width: 900, height: 120)
        let window = NSWindow(
            contentRect: hosting.frame,
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.contentView = hosting
        hosting.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(1))
        hosting.layoutSubtreeIfNeeded()

        var popUps: [NSPopUpButton] = []
        popUpButtons(in: hosting, into: &popUps)
        return popUps.first { $0.itemTitles.contains(WorkStage.report.label) }
    }

    private func popUpButtons(in view: NSView, into found: inout [NSPopUpButton]) {
        if let popUp = view as? NSPopUpButton { found.append(popUp) }
        for child in view.subviews { popUpButtons(in: child, into: &found) }
    }

    // MARK: writing the file

    /// Generate Report from the stage writes the bytes the File menu writes.
    @Test func generatesTheReportTheFileMenuWrites() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)
        let fromTheMenu = try #require(
            await ReportExporter(session: model).data(for: .markdown)
        )

        project.reportFormat = .markdown
        await project.generateReport()

        let path = try #require(project.reportPath)
        #expect(path == "/work/threatmodel/payments.md")
        #expect(
            useCases.project.text(at: path) == String(decoding: fromTheMenu.data, as: UTF8.self)
        )
    }

    /// The format picker names which file the verb writes. HTML goes where the
    /// person says.
    @Test func writesTheFormatThePickerNames() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)
        let fromTheMenu = try #require(await ReportExporter(session: model).data(for: .html))
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("report-stage-\(UUID().uuidString).html")

        project.reportFormat = .html
        await project.generateReport(chooseFile: { _, _ in url })

        #expect(project.reportPath == url.path)
        #expect(try Data(contentsOf: url) == fromTheMenu.data)
        try? FileManager.default.removeItem(at: url)
    }
}
