import AppKit
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The four stages of the analyst's work, measured in a real window.
///
/// A stage states which columns the window draws. Architecture draws the
/// palette, the diagram and what the system takes on trust. Attack Trees
/// draws the trees, the tree canvas and the selected node. Threats drops the
/// palette. Controls drops the diagram as well, so the answers take the whole
/// window.
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
    /// Architecture, because a tree names elements the architecture states.
    @Test func listsTheFourStagesInOrder() {
        #expect(WorkStage.allCases == [.architecture, .attackTrees, .threats, .controls])
        #expect(WorkStage.attackTrees.label == "Attack Trees")
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

    // MARK: what a stage draws

    /// True when the picture holds more than one colour, which tells a view
    /// that drew its content from one that drew a blank rectangle.
    private func hasContent(_ image: NSBitmapImageRep) -> Bool {
        var seen: Set<String> = []
        let across = stride(from: 4, to: image.pixelsWide - 4, by: max(1, image.pixelsWide / 40))
        let down = stride(from: 4, to: image.pixelsHigh - 4, by: max(1, image.pixelsHigh / 40))
        for x in across {
            for y in down {
                guard let colour = image.colorAt(x: x, y: y) else { continue }
                seen.insert(
                    String(
                        format: "%.2f,%.2f,%.2f",
                        colour.redComponent,
                        colour.greenComponent,
                        colour.blueComponent
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
}
