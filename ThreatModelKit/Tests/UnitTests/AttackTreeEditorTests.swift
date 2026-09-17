import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit
import TestSupport

@Suite("Writing an attack tree from the window")
struct AttackTreeEditorTests {
    private let app = TestDependencies()

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "db" {
        technology = "aws-rds"
        data       = "restricted"
      }

      flow api -> db
    }

    """

    private let oneTree = """
    attack_trees for "Payments" {
      tree "read-every-record" {
        name           = "Read every record"
        raises_risk_by = 40

        goal "misconfiguration" on component "db"

        any_of {
          step "credential-theft" on component "api"
        }
      }
    }

    """

    private func aProject(holdingATree: Bool = false) {
        app.project.put(payments, at: "/work/threatmodel/payments.arch")
        if holdingATree {
            app.project.put(oneTree, at: "/work/threatmodel/payments.attacktree")
        }
    }

    private func tree(_ id: String = "new-tree", raisesRiskBy: Int = 25) -> SourceAttackTree {
        SourceAttackTree(
            id: id,
            name: "A new tree",
            description: "What a person wrote in the window.",
            raisesRiskBy: raisesRiskBy,
            goal: SourceTreeTarget(
                threatId: "misconfiguration",
                sourceKind: "component",
                sourceId: "db"
            ),
            root: .any([
                .step(
                    SourceTreeStep(
                        target: SourceTreeTarget(
                            threatId: "credential-theft",
                            sourceKind: "component",
                            sourceId: "api"
                        ),
                        note: "A public exploit exists."
                    )
                )
            ])
        )
    }

    // MARK: reading what the file states

    @Test func listsTheTreesTheFileStates() {
        aProject(holdingATree: true)

        let response = app.listAttackTreeSources()
            .execute(ListAttackTreeSourcesRequest(root: "/work", systemName: "payments"))

        guard case .listed(let trees, let path, _) = response else {
            Issue.record("the file did not read: \(response)")
            return
        }
        #expect(trees.map(\.id) == ["read-every-record"])
        #expect(path == "/work/threatmodel/payments.attacktree")
    }

    /// The file's own `catalogue` tag reads back, so the window can offer
    /// the same 'take the catalogue in use' control the architecture stage
    /// offers for the `.arch` file.
    @Test func listsTheCatalogueTagTheFileStates() {
        aProject()
        app.project.put(
            """
            attack_trees for "Payments" {
              catalogue = "v0.0.1"

              tree "read-every-record" {
                raises_risk_by = 40

                goal "misconfiguration" on component "db"

                any_of {
                  step "credential-theft" on component "api"
                }
              }
            }

            """,
            at: "/work/threatmodel/payments.attacktree"
        )

        let response = app.listAttackTreeSources()
            .execute(ListAttackTreeSourcesRequest(root: "/work", systemName: "payments"))

        guard case .listed(_, _, let catalogueTag) = response else {
            Issue.record("the file did not read: \(response)")
            return
        }
        #expect(catalogueTag == "v0.0.1")
    }

    /// A file that names no tag states none: naming one is the person's to
    /// do.
    @Test func aFileThatStatesNoTagListsNoCatalogueTag() {
        aProject(holdingATree: true)

        let response = app.listAttackTreeSources()
            .execute(ListAttackTreeSourcesRequest(root: "/work", systemName: "payments"))

        guard case .listed(_, _, let catalogueTag) = response else {
            Issue.record("the file did not read: \(response)")
            return
        }
        #expect(catalogueTag == nil)
    }

    /// A system with no file yet states no tree, so writing the first tree
    /// writes the file.
    @Test func aSystemWithNoFileStatesNoTree() {
        aProject()

        let response = app.listAttackTreeSources()
            .execute(ListAttackTreeSourcesRequest(root: "/work", systemName: "payments"))

        guard case .listed(let trees, _, _) = response else {
            Issue.record("the file did not read: \(response)")
            return
        }
        #expect(trees.isEmpty)
    }

    @Test func saysWhenTheProjectHoldsNoSuchSystem() {
        aProject()

        #expect(
            app.listAttackTreeSources()
                .execute(ListAttackTreeSourcesRequest(root: "/work", systemName: "ledger"))
                == .noSuchSystem
        )
    }

    // MARK: writing one

    @Test func writesTheFirstTreeAndItsFile() throws {
        aProject()

        let response = app.writeAttackTree()
            .execute(
                WriteAttackTreeRequest(
                    root: "/work",
                    systemName: "payments",
                    systemDisplayName: "Payments",
                    tree: tree()
                )
            )

        guard case .written(let path, let count) = response else {
            Issue.record("the tree was not written: \(response)")
            return
        }
        #expect(count == 1)
        let written = try #require(app.project.text(at: path))
        #expect(written.contains("attack_trees for \"Payments\" {"))
        #expect(written.contains("tree \"new-tree\" {"))
        #expect(written.contains("raises_risk_by = 25"))
        #expect(written.contains("goal \"misconfiguration\" on component \"db\""))
        #expect(written.contains("step \"credential-theft\" on component \"api\""))
        #expect(written.contains("note = \"A public exploit exists.\""))
    }

    /// A person changing one tree is deciding nothing about the rest.
    @Test func writesTheOtherTreesBackUnchanged() throws {
        aProject(holdingATree: true)

        _ = app.writeAttackTree()
            .execute(
                WriteAttackTreeRequest(
                    root: "/work",
                    systemName: "payments",
                    systemDisplayName: "Payments",
                    tree: tree()
                )
            )

        let written = try #require(
            app.project.text(at: "/work/threatmodel/payments.attacktree")
        )
        #expect(written.contains("tree \"read-every-record\" {"))
        #expect(written.contains("tree \"new-tree\" {"))
    }

    @Test func writingATreeTwiceChangesTheOneThatIsThere() throws {
        aProject(holdingATree: true)

        let changed = SourceAttackTree(
            id: "read-every-record",
            name: "Read every record again",
            raisesRiskBy: 10,
            goal: SourceTreeTarget(
                threatId: "misconfiguration",
                sourceKind: "component",
                sourceId: "db"
            ),
            root: .any([
                .step(
                    SourceTreeStep(
                        target: SourceTreeTarget(
                            threatId: "credential-theft",
                            sourceKind: "component",
                            sourceId: "api"
                        )
                    )
                )
            ])
        )
        let response = app.writeAttackTree()
            .execute(
                WriteAttackTreeRequest(
                    root: "/work",
                    systemName: "payments",
                    systemDisplayName: "Payments",
                    tree: changed
                )
            )

        guard case .written(_, let count) = response else {
            Issue.record("the tree was not written: \(response)")
            return
        }
        #expect(count == 1)
        let written = try #require(
            app.project.text(at: "/work/threatmodel/payments.attacktree")
        )
        #expect(written.contains("Read every record again"))
        #expect(written.contains("raises_risk_by = 10"))
    }

    @Test func refusesATreeWithNoIdentifier() {
        aProject()

        #expect(
            app.writeAttackTree().execute(
                WriteAttackTreeRequest(root: "/work", systemName: "payments", tree: tree(" "))
            ) == .noId
        )
    }

    @Test func refusesARiskOutsideTheRange() {
        aProject()

        #expect(
            app.writeAttackTree().execute(
                WriteAttackTreeRequest(
                    root: "/work",
                    systemName: "payments",
                    tree: tree("new-tree", raisesRiskBy: 140)
                )
            ) == .riskOutsideTheRange
        )
        #expect(app.project.text(at: "/work/threatmodel/payments.attacktree") == nil)
    }

    /// Writing over a file that does not parse would take a person's work
    /// away.
    @Test func refusesToWriteOverAFileThatDoesNotParse() {
        aProject()
        app.project.put(
            "attack_trees for \"Payments\" {\n  tree \"broken\" { }\n}\n",
            at: "/work/threatmodel/payments.attacktree"
        )

        let response = app.writeAttackTree()
            .execute(
                WriteAttackTreeRequest(
                    root: "/work",
                    systemName: "payments",
                    systemDisplayName: "Payments",
                    tree: tree()
                )
            )

        guard case .cannotWrite = response else {
            Issue.record("the file was written over: \(response)")
            return
        }
    }

    // MARK: taking the catalogue in use

    /// Taking the catalogue in use writes the new tag and keeps every tree.
    @Test func takesTheCatalogueInUseAndKeepsEveryTree() throws {
        aProject(holdingATree: true)
        app.project.put(
            """
            attack_trees for "Payments" {
              catalogue = "v0.0.1"

              tree "read-every-record" {
                raises_risk_by = 40

                goal "misconfiguration" on component "db"

                any_of {
                  step "credential-theft" on component "api"
                }
              }
            }

            """,
            at: "/work/threatmodel/payments.attacktree"
        )

        let response = app.takeAttackTreeCatalogue()
            .execute(
                TakeAttackTreeCatalogueRequest(
                    root: "/work",
                    systemName: "payments",
                    systemDisplayName: "Payments",
                    tag: "v0.0.0"
                )
            )

        guard case .written(let path) = response else {
            Issue.record("the tag was not written: \(response)")
            return
        }
        let written = try #require(app.project.text(at: path))
        #expect(written.contains("catalogue = \"v0.0.0\""))
        #expect(written.contains("v0.0.1") == false)
        #expect(written.contains("tree \"read-every-record\" {"))
    }

    @Test func takingTheCatalogueOnASystemThatDoesNotExistSaysSo() {
        aProject()

        #expect(
            app.takeAttackTreeCatalogue().execute(
                TakeAttackTreeCatalogueRequest(root: "/work", systemName: "ledger", tag: "v0.0.0")
            ) == .noSuchSystem
        )
    }

    // MARK: deleting one

    @Test func deletesOneTreeAndKeepsTheRest() throws {
        aProject(holdingATree: true)
        _ = app.writeAttackTree()
            .execute(
                WriteAttackTreeRequest(
                    root: "/work",
                    systemName: "payments",
                    systemDisplayName: "Payments",
                    tree: tree()
                )
            )

        let response = app.removeAttackTree()
            .execute(
                RemoveAttackTreeRequest(
                    root: "/work",
                    systemName: "payments",
                    treeId: "read-every-record"
                )
            )

        guard case .removed(_, let count) = response else {
            Issue.record("the tree was not deleted: \(response)")
            return
        }
        #expect(count == 1)
        let written = try #require(
            app.project.text(at: "/work/threatmodel/payments.attacktree")
        )
        #expect(written.contains("read-every-record") == false)
        #expect(written.contains("tree \"new-tree\" {"))
    }

    @Test func saysWhenTheSystemStatesNoSuchTree() {
        aProject(holdingATree: true)

        #expect(
            app.removeAttackTree().execute(
                RemoveAttackTreeRequest(root: "/work", systemName: "payments", treeId: "nothing")
            ) == .noSuchTree
        )
    }

    // MARK: the same file either way

    /// A tree written from the window and the same tree written by
    /// `threatmodeller format` are the same bytes: one writer states the
    /// canonical shape.
    @Test func writesTheFileFormatWrites() throws {
        aProject()
        _ = app.writeAttackTree()
            .execute(
                WriteAttackTreeRequest(
                    root: "/work",
                    systemName: "payments",
                    systemDisplayName: "Payments",
                    tree: tree()
                )
            )
        let fromTheWindow = try #require(
            app.project.text(at: "/work/threatmodel/payments.attacktree")
        )

        let source = HclAttackTreeSource()
        let read = try #require(source.read(fromTheWindow).source)
        let formatted = source.write(read)

        #expect(formatted == fromTheWindow)
    }

    /// The model scores the tree the window wrote, the way it scores one a
    /// person typed.
    @Test func theModelScoresATreeTheWindowWrote() throws {
        aProject()
        _ = app.writeAttackTree()
            .execute(
                WriteAttackTreeRequest(
                    root: "/work",
                    systemName: "payments",
                    systemDisplayName: "Payments",
                    tree: tree()
                )
            )
        let written = try #require(
            app.project.text(at: "/work/threatmodel/payments.attacktree")
        )

        _ = app.importArchitecture().execute(
            ImportArchitectureRequest(text: payments, attackTreeText: written)
        )
        let assessment = app.assessThreatModel().execute(AssessThreatModelRequest())

        #expect(assessment.attackTrees.map(\.id) == ["new-tree"])
        #expect(
            assessment.attackTrees.first?.isStale == false,
            Comment(
                rawValue: (assessment.attackTrees.first.map { tree in
                    "goal \(tree.goal.value), steps "
                        + tree.steps.map { "\($0.key.value) \($0.state)" }
                            .joined(separator: ", ")
                } ?? "the model bound no tree")
            )
        )
    }
}
