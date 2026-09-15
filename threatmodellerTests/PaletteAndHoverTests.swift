import CoreGraphics
import Foundation
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Finding a technology in the palette.
@MainActor
@Suite("Searching the palette")
struct PaletteSearchTests {
    private func palette() -> [ListedProvider] {
        ThreatModelSession(useCases: TestDependencies()).palette
    }

    @Test func narrowsByName() {
        let found = PaletteSearch.narrow(palette(), to: "EC2")

        let technologies = PaletteSearch.technologies(of: found)
        #expect(technologies.isEmpty == false)
        #expect(technologies.allSatisfy {
            $0.name.lowercased().contains("ec2") || $0.description.lowercased().contains("ec2")
        })
    }

    @Test func narrowsByDescription() {
        let found = PaletteSearch.narrow(palette(), to: "database")

        #expect(PaletteSearch.technologies(of: found).contains { $0.id == "aws-rds" })
    }

    @Test func dropsAProviderAndACategoryWithNoMatch() {
        let found = PaletteSearch.narrow(palette(), to: "EC2")

        #expect(found.allSatisfy { $0.categories.isEmpty == false })
        #expect(found.allSatisfy { $0.categories.allSatisfy { $0.technologies.isEmpty == false } })
    }

    @Test func emptyWordsGiveThePaletteBackWhole() {
        let whole = palette()

        #expect(PaletteSearch.narrow(whole, to: "") == whole)
        #expect(PaletteSearch.narrow(whole, to: "   ") == whole)
    }

    @Test func wordsNothingMatchesGiveNothing() {
        #expect(PaletteSearch.narrow(palette(), to: "not-a-technology").isEmpty)
    }

    @Test func thePaletteStatesHowManyThreatsATechnologyRaises() throws {
        let ec2 = try #require(
            PaletteSearch.technologies(of: palette()).first { $0.id == "aws-ec2" }
        )

        #expect(ec2.threatCount > 0)
        #expect(TechnologyRow.hover(over: ec2).contains("Raises \(ec2.threatCount) threats."))
    }
}

/// What the diagram says on hover.
@MainActor
@Suite("Hovering the diagram")
struct HoverTextTests {
    private func drawn() -> ThreatModelSession {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 40, y: 40)
        _ = session.addZone(x: 0, y: 0, width: 600, height: 500)
        return session
    }

    @Test func aNodeStatesWhatItIsWhereItSitsAndWhatIsOpen() throws {
        let session = drawn()
        let component = try #require(session.canvas.components.first)
        let zone = try #require(session.canvas.zones.first)
        let risk = session.elementRisks["component:\(component.id)"]

        let said = HoverText.node(component, zoneName: zone.name, risk: risk)

        #expect(said.contains("aws-ec2"))
        #expect(said.contains("In \(zone.name)"))
        #expect(said.contains("open threats of"))
    }

    @Test func aNodeInNoZoneSaysSo() throws {
        let session = ThreatModelSession(useCases: TestDependencies())
        session.add(technologyId: "aws-ec2", x: 2000, y: 2000)
        let component = try #require(session.canvas.components.first)

        #expect(
            HoverText.node(component, zoneName: nil, risk: nil).contains("In no zone")
        )
    }

    /// A node with four open threats names the three worst and states the
    /// fourth.
    @Test func aBadgeNamesTheThreeWorstAndCountsTheRest() {
        let risk = ElementRisk(
            sourceId: "component:api",
            openCount: 4,
            totalCount: 6,
            highestLevelId: "critical",
            worstOpen: [
                OpenThreat(name: "Credential Theft", score: 12),
                OpenThreat(name: "Data Exfiltration", score: 9),
                OpenThreat(name: "Misconfiguration", score: 6)
            ]
        )

        let said = HoverText.badge(risk)

        #expect(said == "Credential Theft — 12\nData Exfiltration — 9\nMisconfiguration — 6\nand 1 more")
    }

    @Test func aBadgeWithNothingOpenSaysSo() {
        #expect(HoverText.badge(nil) == "Nothing open")
        #expect(
            HoverText.badge(
                ElementRisk(sourceId: "component:api", openCount: 0, totalCount: 3, highestLevelId: "low")
            ) == "Nothing open"
        )
    }

    @Test func theRollupNamesTheWorstOpenThreatsWorstFirst() throws {
        let session = drawn()
        let component = try #require(session.canvas.components.first)
        let risk = try #require(session.elementRisks["component:\(component.id)"])

        #expect(risk.worstOpen.count <= 3)
        #expect(risk.worstOpen == risk.worstOpen.sorted { $0.score > $1.score })
    }

    @Test func aZoneStatesItsKindAndWhatIsOpen() throws {
        let session = drawn()
        let zone = try #require(session.canvas.zones.first)

        let said = HoverText.zone(zone, risk: session.elementRisks["zone:\(zone.id)"])

        #expect(said.contains("private zone"))
        #expect(said.contains("open threats of") || said.contains("No threats"))
    }
}

/// The picture the samples browser draws.
@MainActor
@Suite("Previewing an example")
struct SamplePreviewTests {
    private func session() -> ThreatModelSession {
        ThreatModelSession(useCases: TestDependencies())
    }

    @Test func drawsASampleFromItsOwnDocument() throws {
        let session = session()
        let sample = try #require(session.samples.first)

        let drawn = try #require(session.samplePicture(sample.id))

        #expect(drawn.components.isEmpty == false)
        // Nothing on screen changed: the preview reads, it does not open.
        #expect(session.canvas.components.isEmpty)
    }

    @Test func saysNothingForASampleThatIsNotThere() {
        #expect(session().samplePicture("not-a-sample") == nil)
    }

    @Test func fitsThePictureInTheRoomThePreviewHas() {
        let wide = SampleBrowser.previewScale(of: CGSize(width: 4000, height: 400))
        let small = SampleBrowser.previewScale(of: CGSize(width: 100, height: 100))

        #expect(wide < 1)
        #expect(small == 1)
        #expect(SampleBrowser.previewScale(of: .zero) == 1)
    }
}

/// A technology one system defines, moved into the project's library.
@MainActor
@Suite("Moving a technology to a library")
struct MoveToLibraryTests {
    private let payments = """
    system "Payments" {
      component "api" { technology = "aws-ec2" }
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

    @Test func writesTheTechnologyIntoTheProjectsLibrary() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let technologyId = try #require(
            model.createCustomTechnology(
                name: "Our Ledger",
                categoryId: "database",
                description: "",
                threatIds: [],
                enforcesEncryption: false
            )
        )

        let moved = session.moveTechnologyToLibrary(technologyId, into: "shared")

        #expect(moved == "shared-\(technologyId.replacingOccurrences(of: "custom-", with: ""))")
        #expect(useCases.project.text(at: "/work/threatmodel/library/shared.lib") != nil)
        #expect(session.errorMessage == nil)
    }

    @Test func saysSoWhenTheLibraryAlreadyStatesIt() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        let technologyId = try #require(
            model.createCustomTechnology(
                name: "Our Ledger",
                categoryId: "database",
                description: "",
                threatIds: [],
                enforcesEncryption: false
            )
        )
        let bare = technologyId.replacingOccurrences(of: "custom-", with: "")
        useCases.project.put(
            """
            library "shared" {
              technology "\(bare)" {
                name     = "Our Ledger"
                category = "database"
              }
            }
            """,
            at: "/work/threatmodel/library/shared.lib"
        )

        let moved = session.moveTechnologyToLibrary(technologyId, into: "shared")

        #expect(moved == nil)
        #expect(session.errorMessage?.contains("already states") == true)
    }
}
