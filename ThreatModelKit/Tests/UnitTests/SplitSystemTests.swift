import ArchitectureDSL
import Testing
import ThreatModelKit
import TestSupport

/// A system split across files, which composes into one system.
@Suite("A system split across files")
struct SplitSystemTests {
    private let header = """
    system "Payments" {
      catalogue      = "v1.0.0"
      risk_tolerance = "medium"

      assumption "segmented" {
        text = "The network is segmented."
      }
    }
    """

    private let edge = """
    zone "edge" {
      kind = "public"

      component "waf" { technology = "aws-waf" }
    }
    """

    private let ledger = """
    component "api" {
      technology = "aws-ec2"
      data       = "confidential"
    }

    flow waf -> api
    """

    private func parts() -> [SourcePart] {
        [
            SourcePart(file: "arch/edge.arch", text: edge),
            SourcePart(file: "arch/ledger.arch", text: ledger),
            SourcePart(file: "arch/payments.arch", text: header)
        ]
    }

    private func merged(_ parts: [SourcePart]) -> MergedArchitecture.Merged {
        HclArchitectureSource().read(parts, named: "payments")
    }

    // MARK: the merge

    @Test func joinsEveryFileIntoOneSystem() throws {
        let read = merged(parts())

        let source = try #require(read.source)
        #expect(source.systemName == "Payments")
        #expect(source.catalogueTag == "v1.0.0")
        #expect(source.riskTolerance == "medium")
        #expect(source.assumptions.map(\.label) == ["segmented"])
        #expect(source.zones.map(\.id) == ["edge"])
        #expect(source.everyComponent.map(\.id).sorted() == ["api", "waf"])
        #expect(source.flows.count == 1)
    }

    /// A flow in one file may name a component another file declares. That is
    /// the point of the split.
    @Test func aFlowMayJoinTwoFiles() throws {
        let read = merged(parts())

        #expect(read.hasErrors == false)
        let flow = try #require(read.source?.flows.first)
        #expect(flow.sourceId == "waf")
        #expect(flow.targetId == "api")
    }

    @Test func remembersWhichFileEachBlockCameFrom() {
        let read = merged(parts())

        #expect(read.origins[.zone("edge")] == "arch/edge.arch")
        #expect(read.origins[.component("waf")] == "arch/edge.arch")
        #expect(read.origins[.component("api")] == "arch/ledger.arch")
        #expect(read.origins[.assumption("segmented")] == "arch/payments.arch")
    }

    // MARK: what the merge refuses

    @Test func refusesASystemWithNoHeader() {
        let read = merged([SourcePart(file: "arch/edge.arch", text: edge)])

        #expect(read.source == nil)
        #expect(
            read.diagnostics.contains {
                $0.message == "the system \"payments\" holds no file with a system block"
            }
        )
    }

    @Test func refusesTwoHeaders() {
        let read = merged([
            SourcePart(file: "arch/payments.arch", text: header),
            SourcePart(file: "arch/other.arch", text: "system \"Payments\" { }")
        ])

        #expect(read.source == nil)
        #expect(
            read.diagnostics.contains {
                $0.message.contains("states a system block twice")
                    && $0.message.contains("arch/payments.arch")
                    && $0.message.contains("arch/other.arch")
            }
        )
    }

    @Test func namesBothFilesWhenAComponentIsDeclaredTwice() {
        let read = merged([
            SourcePart(file: "arch/payments.arch", text: header),
            SourcePart(file: "arch/a.arch", text: "component \"api\" { technology = \"aws-ec2\" }"),
            SourcePart(file: "arch/b.arch", text: "component \"api\" { technology = \"aws-rds\" }")
        ])

        #expect(read.source == nil)
        #expect(
            read.diagnostics.contains {
                $0.message == "the component \"api\" is declared twice: arch/a.arch and arch/b.arch"
            }
        )
    }

    @Test func namesTheSystemWhenAFlowNamesNothing() {
        let read = merged([
            SourcePart(file: "arch/payments.arch", text: header),
            SourcePart(
                file: "arch/a.arch",
                text: "component \"api\" { technology = \"aws-ec2\" }\n\nflow api -> ghost"
            )
        ])

        #expect(read.source == nil)
        #expect(
            read.diagnostics.contains {
                $0.message == "the flow ends at \"ghost\", which this system does not declare"
            }
        )
    }

    @Test func aFaultNamesTheFileItIsIn() {
        let read = merged([
            SourcePart(file: "arch/payments.arch", text: header),
            SourcePart(file: "arch/broken.arch", text: "component \"api\" { }")
        ])

        let said = read.diagnostics.map { $0.described(in: "the system") }
        #expect(said.contains { $0.hasPrefix("arch/broken.arch:") })
    }

    @Test func warnsWhenTheDirectoryAndTheLabelDiffer() {
        let read = merged([SourcePart(file: "arch/payments.arch", text: header)])

        #expect(
            read.warnings.contains {
                $0.message == "the directory is \"payments\" and the system block says \"Payments\""
            }
        )
        #expect(read.source?.systemName == "Payments")
    }

    // MARK: a project that holds one

    private func aSplitProject() -> TestDependencies {
        let app = TestDependencies()
        app.project.put(header, at: "/work/threatmodel/payments/arch/payments.arch")
        app.project.put(edge, at: "/work/threatmodel/payments/arch/edge.arch")
        app.project.put(ledger, at: "/work/threatmodel/payments/arch/ledger.arch")
        return app
    }

    @Test func aProjectFindsASplitSystem() throws {
        let layout = try aSplitProject().project.discover(root: "/work")

        let system = try #require(layout.system(named: "payments"))
        #expect(system.isSplit)
        #expect(system.architecturePaths.count == 3)
        #expect(system.headerPath == "/work/threatmodel/payments/arch/payments.arch")
        #expect(system.reportPath == "/work/threatmodel/payments/payments.md")
    }

    @Test func aProjectHoldsBothShapesAtOnce() throws {
        let app = aSplitProject()
        app.project.put("system \"Ledger\" { }", at: "/work/threatmodel/ledger.arch")

        let layout = try app.project.discover(root: "/work")

        #expect(layout.systems.map(\.name) == ["ledger", "payments"])
        #expect(layout.system(named: "ledger")?.isSplit == false)
    }

    @Test func theLibraryDirectoryIsNotASystem() throws {
        let app = aSplitProject()
        app.project.put(
            "library \"acme\" { }",
            at: "/work/threatmodel/library/acme.lib"
        )

        let layout = try app.project.discover(root: "/work")

        #expect(layout.systems.map(\.name) == ["payments"])
        #expect(layout.libraryPaths.count == 1)
    }

    @Test func opensASplitSystemAsOneModel() throws {
        let app = aSplitProject()

        let response = app.openSystem().execute(
            OpenSystemRequest(root: "/work", systemName: "payments")
        )

        guard case .opened(let name, _, _) = response else {
            Issue.record("expected the system to open, got \(response)")
            return
        }
        #expect(name == "Payments")
        #expect(app.modelStore.current().components.map(\.id.value).sorted() == ["api", "waf"])
        #expect(app.modelStore.current().zones.count == 1)
    }

    /// A file a person double-clicks inside a subproject opens the project on
    /// that system.
    @Test func aFileInsideASubprojectNamesItsSystem() {
        let found = ProjectConvention.system(atPath: "/work/threatmodel/payments/arch/edge.arch")

        #expect(found?.root == "/work")
        #expect(found?.systemName == "payments")
    }

    @Test func aFlatFileStillNamesItsSystem() {
        let found = ProjectConvention.system(atPath: "/work/threatmodel/payments.arch")

        #expect(found?.root == "/work")
        #expect(found?.systemName == "payments")
    }

    // MARK: the controls mirror

    @Test func anAnswerGoesToTheFileThatMirrorsItsArchitecture() throws {
        let app = aSplitProject()
        let layout = try app.project.discover(root: "/work")
        let system = try #require(layout.system(named: "payments"))

        #expect(
            system.controlsPath(mirroring: "/work/threatmodel/payments/arch/edge.arch")
                == "/work/threatmodel/payments/controls/edge.controls"
        )
    }

    @Test func aFlatSystemAnswersBesideItsArchitecture() throws {
        let app = TestDependencies()
        app.project.put("system \"Ledger\" { }", at: "/work/threatmodel/ledger.arch")
        let layout = try app.project.discover(root: "/work")
        let system = try #require(layout.system(named: "ledger"))

        #expect(
            system.controlsPath(mirroring: "/work/threatmodel/ledger.arch")
                == "/work/threatmodel/ledger.controls"
        )
    }

    // MARK: the part file, written back

    @Test func aPartIsWrittenWithNoSystemBlock() throws {
        let read = HclArchitectureSource().readPart(edge)
        let source = try #require(read.source)

        let written = HclArchitectureSource().writePart(source)

        #expect(written.hasPrefix("zone \"edge\" {"))
        #expect(written.contains("system \"") == false)
    }

    @Test func aRewriteOfAPartChangesNothingTheSecondTime() throws {
        let source = try #require(HclArchitectureSource().readPart(edge).source)
        let once = HclArchitectureSource().writePart(source)

        let again = try #require(HclArchitectureSource().readPart(once).source)

        #expect(HclArchitectureSource().writePart(again) == once)
    }
}

/// Writing a split system back to the files it came from.
@Suite("Saving a split system")
struct SaveSplitSystemTests {
    private let header = """
    system "Payments" {
      catalogue = "v1.0.0"
    }
    """

    private let edge = """
    component "waf" {
      technology = "aws-waf"
    }
    """

    private let ledger = """
    component "api" {
      technology = "aws-ec2"
      data       = "confidential"
    }

    flow waf -> api
    """

    private func aSplitProject() -> TestDependencies {
        let app = TestDependencies()
        app.project.put(header, at: "/work/threatmodel/payments/arch/payments.arch")
        app.project.put(edge, at: "/work/threatmodel/payments/arch/edge.arch")
        app.project.put(ledger, at: "/work/threatmodel/payments/arch/ledger.arch")
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        return app
    }

    @Test func writesEachBlockBackToTheFileItCameFrom() throws {
        let app = aSplitProject()

        let response = app.saveSystem().execute(
            SaveSystemRequest(root: "/work", systemName: "payments")
        )

        #expect(response == .saved(architecturePath: "/work/threatmodel/payments/arch/payments.arch"))
        let edgeFile = try #require(app.project.text(at: "/work/threatmodel/payments/arch/edge.arch"))
        let ledgerFile = try #require(
            app.project.text(at: "/work/threatmodel/payments/arch/ledger.arch")
        )
        #expect(edgeFile.contains("component \"waf\""))
        #expect(edgeFile.contains("component \"api\"") == false)
        #expect(ledgerFile.contains("component \"api\""))
        #expect(ledgerFile.contains("flow waf -> api"))
    }

    @Test func theHeaderFileKeepsTheSystemBlock() throws {
        let app = aSplitProject()

        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))

        let headerFile = try #require(
            app.project.text(at: "/work/threatmodel/payments/arch/payments.arch")
        )
        #expect(headerFile.hasPrefix("system \"Payments\" {"))
        #expect(headerFile.contains("catalogue = \"v1.0.0\""))
        #expect(headerFile.contains("component \"waf\"") == false)
    }

    /// A block a person adds in the application goes into the header file.
    @Test func aNewComponentGoesIntoTheHeaderFile() throws {
        let app = aSplitProject()
        _ = app.addComponent().execute(
            AddComponentRequest(technologyId: "aws-rds", x: 0, y: 0, sensitivity: "internal")
        )

        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))

        let headerFile = try #require(
            app.project.text(at: "/work/threatmodel/payments/arch/payments.arch")
        )
        #expect(headerFile.contains("technology = \"aws-rds\""))
    }

    /// A save of a system nobody changed writes the same files again, so a
    /// rewrite produces no diff.
    @Test func aSaveOfAnUnchangedSystemWritesTheSameFiles() throws {
        let app = aSplitProject()
        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))
        let once = app.project.text(at: "/work/threatmodel/payments/arch/edge.arch")

        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))

        #expect(app.project.text(at: "/work/threatmodel/payments/arch/edge.arch") == once)
    }

    @Test func theSavedFilesReadBackAsTheSameSystem() throws {
        let app = aSplitProject()
        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))

        let fresh = TestDependencies()
        for path in [
            "/work/threatmodel/payments/arch/payments.arch",
            "/work/threatmodel/payments/arch/edge.arch",
            "/work/threatmodel/payments/arch/ledger.arch"
        ] {
            fresh.project.put(try #require(app.project.text(at: path)), at: path)
        }

        let response = fresh.openSystem().execute(
            OpenSystemRequest(root: "/work", systemName: "payments")
        )

        guard case .opened = response else {
            Issue.record("expected the saved files to open, got \(response)")
            return
        }
        #expect(fresh.modelStore.current().components.count == 2)
        #expect(fresh.modelStore.current().connections.count == 1)
    }
}
