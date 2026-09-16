import AppKit
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The five stages of the analyst's work, measured in a real window.
///
/// A stage states which columns the window draws. Architecture draws the
/// palette, the diagram and what the system takes on trust. Attack Trees
/// draws the trees, the tree canvas and the selected node. Threats drops the
/// palette. Controls drops the diagram as well, so the answers take the whole
/// window. Report draws the sections, the reading column and the report's
/// controls.
@MainActor
struct AnalystFlowTests {
    private func aDrawnProject() async -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" {
                technology = "aws-ec2"
                data       = "confidential"
              }
              component "store" {
                technology = "aws-rds"
                data       = "confidential"
              }
            }

            """,
            at: "/work/threatmodel/payments.arch"
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return session
    }

    /// The columns of a view, laid out in a window.
    private func columnCount(of view: some View) -> Int {
        let host = NSHostingView(rootView: view.frame(width: 1200, height: 800))
        host.frame = CGRect(x: 0, y: 0, width: 1200, height: 800)
        let window = NSWindow(
            contentRect: host.frame,
            styleMask: [.titled],
            backing: .buffered,
            defer: false
        )
        window.contentView = host
        window.orderBack(nil)
        host.layoutSubtreeIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.6))

        func splits(in view: NSView) -> [NSSplitView] {
            var found: [NSSplitView] = []
            if let split = view as? NSSplitView { found.append(split) }
            for child in view.subviews { found += splits(in: child) }
            return found
        }
        let count = splits(in: host).first?.arrangedSubviews.count ?? 0
        window.orderOut(nil)
        return count
    }

    private func columns(_ stage: WorkStage, of project: ProjectSession) throws -> Int {
        let model = try #require(project.model)
        return columnCount(
            of: ProjectColumns(
                project: project,
                session: model,
                canvas: CanvasState(),
                stage: .constant(stage)
            )
        )
    }

    @Test func drawsThePaletteTheDiagramAndTheAssumptionsWhileDrawingTheArchitecture() async throws {
        let project = await aDrawnProject()

        #expect(try columns(.architecture, of: project) == 3)
    }

    /// The stages, in the order the panel lists them: Attack Trees sits after
    /// Architecture, because a tree names elements the architecture states,
    /// and Report sits last, because reading the report is the last thing a
    /// person does.
    @Test func listsTheFiveStagesInOrder() {
        #expect(
            WorkStage.allCases == [.architecture, .attackTrees, .threats, .controls, .report]
        )
        #expect(WorkStage.attackTrees.label == "Attack Trees")
        #expect(WorkStage.report.label == "Report")
    }

    /// A tree is drawn with the trees on the left, the canvas in the middle
    /// and the selected node on the right.
    @Test func drawsTheTreesTheTreeCanvasAndTheSelectedNodeWhileDrawingAttackTrees() async throws {
        let project = await aDrawnProject()

        #expect(try columns(.attackTrees, of: project) == 3)
    }

    /// Nothing is added to the diagram at this stage, so the palette is a
    /// column of nothing the analyst needs.
    @Test func dropsThePaletteWhileReadingTheThreats() async throws {
        let project = await aDrawnProject()

        #expect(try columns(.threats, of: project) == 2)
    }

    /// Answering a control is reading and typing. The diagram says nothing
    /// about it, so the answers take the window.
    @Test func dropsTheDiagramWhileAnsweringTheControls() async throws {
        let project = await aDrawnProject()

        #expect(try columns(.controls, of: project) == 0)
    }

    /// The report is read with the sections on the left, the sections
    /// themselves in the middle and the report's own controls on the right.
    @Test func drawsTheSectionsTheReadingAndTheControlsWhileReadingTheReport() async throws {
        let project = await aDrawnProject()

        #expect(try columns(.report, of: project) == 3)
    }

    // MARK: what a stage draws

    /// True when the picture holds more than one pixel value, which tells a
    /// view that drew its content from one that drew a blank rectangle.
    ///
    /// A pixel value is the colour and the alpha together. A panel that draws
    /// no background of its own, such as `TreeSelectionPanel`, draws white
    /// text on nothing, so every pixel reads white and only the alpha says
    /// which pixel the panel drew. A machine with no screen leaves the
    /// untouched pixels at one colour, so a check that reads the colour alone
    /// calls such a panel blank.
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

    private func expectDrawn(
        _ view: some View,
        width: CGFloat = 420,
        height: CGFloat = 640,
        _ what: String
    ) {
        guard let drawn = hostedDrawing(of: view, width: width, height: height) else {
            Issue.record("\(what) drew nothing at all")
            return
        }
        #expect(hasContent(drawn.image), "\(what) drew a blank rectangle")
    }

    /// A model with two components and an assumption, which is what the
    /// architecture stage's third column draws.
    private func aModelThatTakesSomethingOnTrust() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 0, y: 0)
        session.add(technologyId: "aws-rds", x: 400, y: 0)
        session.setAssumption(
            label: "network-segmented",
            text: "The subnet holding the store takes no traffic from the internet.",
            owner: "platform"
        )
        return session
    }

    @Test func drawsWhatTheSystemTakesOnTrust() {
        expectDrawn(AssumptionsPanel(session: aModelThatTakesSomethingOnTrust()), "the assumptions panel")
    }

    @Test func drawsTheSheetThatSaysHowOftenAThreatHappens() throws {
        let session = aModelThatTakesSomethingOnTrust()
        let threat = try #require(session.threats.first)
        let project = ProjectSession(
            useCases: TestDependencies(),
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )

        expectDrawn(
            LikelihoodSheet(threat: threat, session: session, project: project),
            width: 460,
            height: 560,
            "the likelihood sheet"
        )
    }

    @Test func drawsTheSheetThatNamesWhatOneComponentLowersOnAnother() throws {
        let session = aModelThatTakesSomethingOnTrust()
        let components = session.canvas.components

        expectDrawn(
            MitigatesSheet(
                session: session,
                protector: try #require(components.first),
                protected: try #require(components.last),
                existing: nil
            ),
            width: 520,
            height: 560,
            "the mitigates sheet"
        )
    }

    @Test func drawsTheBarThatOffersTheMitigatesEdge() throws {
        let session = aModelThatTakesSomethingOnTrust()
        let components = session.canvas.components

        expectDrawn(
            MitigatesPanel(
                session: session,
                source: try #require(components.first),
                target: try #require(components.last)
            ),
            width: 700,
            height: 60,
            "the mitigates bar"
        )
    }

    @Test func drawsTheThreatListTheThreatsStageShows() {
        expectDrawn(
            ThreatSidebar(session: aModelThatTakesSomethingOnTrust(), focus: .likelihood),
            "the threat list of the threats stage"
        )
    }

    @Test func drawsTheTreeSidebarTheAttackTreesStageShows() async throws {
        let project = await aDrawnProject()
        let model = try #require(project.model)

        expectDrawn(
            TreeSidebar(
                project: project,
                session: model,
                editor: TreeEditor(),
                canvas: TreeCanvasState(),
                elements: TreeElement.list(
                    threats: model.threats,
                    components: model.canvas.components,
                    connections: model.canvas.connections,
                    zones: model.canvas.zones
                ),
                bound: []
            ),
            "the tree sidebar of the attack trees stage"
        )
    }

    @Test func drawsTheSelectedNodeTheAttackTreesStageShows() {
        let editor = TreeEditor()
        editor.open(
            SourceAttackTree(
                id: "t",
                name: "T",
                description: nil,
                raisesRiskBy: 10,
                goal: SourceTreeTarget(threatId: "exfiltration", sourceKind: "component", sourceId: "db"),
                root: .step(SourceTreeStep(
                    target: SourceTreeTarget(threatId: "ssrf", sourceKind: "component", sourceId: "api"),
                    note: nil
                ))
            ),
            threats: []
        )
        let canvas = TreeCanvasState()
        canvas.select(editor.graph.nodes[1].id, addingToSelection: false)

        expectDrawn(
            TreeSelectionPanel(editor: editor, canvas: canvas, bound: nil),
            "the selected node panel of the attack trees stage"
        )
    }

    // MARK: the answers the architecture no longer raises

    /// A project whose controls file answers a threat on a component the
    /// architecture has since lost.
    private func aProjectWithAStaleAnswer() async -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" { technology = "aws-ec2" }
            }
            """,
            at: "/work/threatmodel/payments.arch"
        )
        useCases.project.put(
            """
            controls for "Payments" {
              stale threat "t-old" on component "gone" {
                control "Something a person answered" { status = "implemented" }
              }
            }
            """,
            at: "/work/threatmodel/payments.controls"
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return session
    }

    @Test func listsTheAnswersTheArchitectureNoLongerRaises() async {
        let project = await aProjectWithAStaleAnswer()

        #expect(project.staleAnswers.map(\.threatId) == ["t-old"])
    }

    @Test func deletesOneAnswerAPersonSaysToDelete() async throws {
        let project = await aProjectWithAStaleAnswer()
        let answer = try #require(project.staleAnswers.first)

        await project.removeStaleAnswer(answer)

        #expect(project.staleAnswers.isEmpty)
        #expect(project.errorMessage == nil)
    }

    @Test func drawsTheAnswersTheArchitectureNoLongerRaises() async {
        let project = await aProjectWithAStaleAnswer()

        expectDrawn(StaleAnswersPanel(project: project), width: 420, height: 140, "the stale answers panel")
    }

    /// A project whose controls file answers two threats the architecture no
    /// longer raises.
    private func aProjectWithTwoStaleAnswers() async -> ProjectSession {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" { technology = "aws-ec2" }
            }
            """,
            at: "/work/threatmodel/payments.arch"
        )
        useCases.project.put(
            """
            controls for "Payments" {
              stale threat "t-old" on component "gone" {
                control "Something a person answered" { status = "implemented" }
              }
              stale threat "t-older" on component "gone-too" {
                control "Something else a person answered" { status = "implemented" }
              }
            }
            """,
            at: "/work/threatmodel/payments.controls"
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return session
    }

    /// A delete has to change what the panel draws at once. The property the
    /// panel reads has to be a stored one the delete sets, not a computed one
    /// `@Observable` never sees change.
    @Test func theRowGoesFromThePanelWhenTheDeleteCompletes() async throws {
        let project = await aProjectWithTwoStaleAnswers()
        let deleted = try #require(
            project.staleAnswers.first { $0.threatId == "t-old" }
        )

        await project.removeStaleAnswer(deleted)

        #expect(project.staleAnswers.map(\.threatId) == ["t-older"])
        #expect(
            StaleAnswersPanel.label(for: project.staleAnswers.count)
                == "1 answer is for a threat this system no longer raises"
        )
        expectDrawn(
            StaleAnswersPanel(project: project),
            width: 420,
            height: 140,
            "the stale answers panel with one answer left"
        )
    }

    @Test func thePanelHidesWhenTheLastStaleAnswerIsDeleted() async throws {
        let project = await aProjectWithAStaleAnswer()
        let answer = try #require(project.staleAnswers.first)

        await project.removeStaleAnswer(answer)

        #expect(project.staleAnswers.isEmpty)
        guard let drawn = hostedDrawing(
            of: StaleAnswersPanel(project: project),
            width: 420,
            height: 140
        ) else {
            Issue.record("the stale answers panel drew nothing at all")
            return
        }
        #expect(hasContent(drawn.image) == false)
    }

    // MARK: deleting every stale answer at once

    /// A project whose controls file answers two threats the architecture no
    /// longer raises, one with only controls and one that holds every other
    /// kind of block a stale stanza can hold.
    private func aProjectWithTwoRichStaleAnswers() async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(
            """
            system "Payments" {
              component "api" { technology = "aws-ec2" }
            }
            """,
            at: "/work/threatmodel/payments.arch"
        )
        useCases.project.put(
            """
            controls for "Payments" {
              stale threat "t-old" on component "gone" {
                control "Answered" { status = "implemented" }
              }

              stale threat "t-older" on component "also-gone" {
                likelihood "no campaign observed" {
                  tier      = "research"
                  rationale = "no known exploitation in the wild"
                }

                severity_override "medium" {
                  rationale = "Scoped credential."
                }

                control "Answered too" { status = "implemented" }

                compensating "Watched by the SIEM" {
                  reduces_risk_by = 40
                  rationale       = "The one account left alerts on use."
                }

                recommendation "adopt-the-guard" {}
              }
            }
            """,
            at: "/work/threatmodel/payments.controls"
        )
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    /// "Delete all" opens the sheet with one row per stale answer, stating
    /// what each stanza holds. Cancel writes nothing.
    @Test func theConfirmationSheetListsWhatEachStaleAnswerHoldsAndCancelWritesNothing() async throws {
        let (project, useCases) = await aProjectWithTwoRichStaleAnswers()
        let before = try #require(
            useCases.project.text(at: "/work/threatmodel/payments.controls")
        )

        let answers = project.staleAnswers
        #expect(answers.count == 2)
        let sparse = try #require(answers.first { $0.threatId == "t-old" })
        #expect(sparse.controlCount == 1)
        #expect(sparse.hasLikelihoodFinding == false)
        #expect(sparse.hasSeverityDecision == false)
        #expect(sparse.compensatingCount == 0)
        #expect(sparse.recommendationCount == 0)
        let rich = try #require(answers.first { $0.threatId == "t-older" })
        #expect(rich.controlCount == 1)
        #expect(rich.hasLikelihoodFinding == true)
        #expect(rich.hasSeverityDecision == true)
        #expect(rich.compensatingCount == 1)
        #expect(rich.recommendationCount == 1)

        expectDrawn(
            StaleAnswersConfirmationSheet(project: project, answers: answers, dismiss: {}),
            width: 640,
            height: 360,
            "the stale answers confirmation sheet"
        )
        // Cancel calls only `dismiss`, so nothing here ever wrote the file.
        #expect(useCases.project.text(at: "/work/threatmodel/payments.controls") == before)
    }

    /// Confirming the sheet deletes every stale answer in one write, and the
    /// panel goes with the last row.
    @Test func confirmingTheSheetDeletesEveryStaleAnswerAndHidesThePanel() async throws {
        let (project, _) = await aProjectWithTwoRichStaleAnswers()

        await project.removeStaleAnswers()

        #expect(project.staleAnswers.isEmpty)
        #expect(project.errorMessage == nil)
        guard let drawn = hostedDrawing(
            of: StaleAnswersPanel(project: project),
            width: 420,
            height: 140
        ) else {
            Issue.record("the stale answers panel drew nothing at all")
            return
        }
        #expect(hasContent(drawn.image) == false)
    }
}
