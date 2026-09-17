import ArchitectureDSL
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// Reading and writing a system asset's description in the window, end to
/// end: the field the assets sheet draws, the `description` line the save
/// writes, and what the parser reads back from it.
///
/// Issue #162: saving from the window blanked an asset's description because
/// the assets sheet called `setSystemAsset` with no description, so the
/// default empty word replaced whatever the file stated.
@MainActor
@Suite("A system asset's description in the window")
struct AssetDescriptionFlowTests {
    private let withDescribedAsset = """
    system "Payments" {
      asset "card-data" {
        name           = "Card data"
        classification = "confidential"
        description    = "The card number and expiry a customer enters."
        owner          = "Payments team"
      }

      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject(_ text: String? = nil) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(text ?? withDescribedAsset, at: "/work/threatmodel/payments.arch")
        let session = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )
        await session.open(root: "/work")
        return (session, useCases)
    }

    private func architecture(_ useCases: TestDependencies) -> String? {
        useCases.project.text(at: "/work/threatmodel/payments.arch")
    }

    // MARK: the round trip

    /// A file with an asset description, an unrelated edit through the sheet,
    /// and a save keep the description: an edit to the owner must not blank
    /// the field the sheet's draft never touched.
    @Test func anUnrelatedEditThroughTheSheetKeepsTheDescription() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        // Read the asset into the form the way the pencil button does, then
        // change the owner alone. The description the read carried over must
        // still write, because the sheet never cleared it.
        let asset = try #require(model.canvas.systemAssets.first)
        let sheet = AssetsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: asset.id,
                name: asset.name,
                classification: asset.classificationId,
                description: asset.description,
                owner: "Fraud team"
            )
        )
        sheet.write()
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("owner          = \"Fraud team\""))
        #expect(written.contains("description    = \"The card number and expiry a customer enters.\""))
    }

    @Test func theListShowsTheDescription() async throws {
        let (session, _) = await aProject()
        let model = try #require(session.model)

        let asset = try #require(model.canvas.systemAssets.first)
        #expect(asset.description == "The card number and expiry a customer enters.")
    }

    @Test func editingAnAssetKeepsItsDescriptionInTheFormWithNoFurtherTyping() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)

        // Read the asset into the form the way the pencil button does, then
        // write it straight back with nothing retyped.
        let asset = try #require(model.canvas.systemAssets.first)
        let sheet = AssetsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: asset.id,
                name: asset.name,
                classification: asset.classificationId,
                description: asset.description,
                owner: asset.owner ?? ""
            )
        )
        sheet.write()
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("description    = \"The card number and expiry a customer enters.\""))
    }

    @Test func writesANewAssetsDescription() async throws {
        let (session, useCases) = await aProject("""
        system "Payments" {
          component "api" {
            technology = "aws-ec2"
          }
        }

        """)
        let model = try #require(session.model)

        let sheet = AssetsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: "card-data",
                name: "Card data",
                classification: "confidential",
                description: "The card number and expiry a customer enters."
            )
        )
        sheet.write()
        await session.save()

        #expect(model.errorMessage == nil)
        let written = try #require(architecture(useCases))
        #expect(written.contains("description    = \"The card number and expiry a customer enters.\""))
    }

    @Test func theParserReadsTheDescriptionBackWithTheSameValue() async throws {
        let (session, useCases) = await aProject()
        let model = try #require(session.model)
        await session.save()

        let text = try #require(architecture(useCases))
        let source = try #require(HclArchitectureSource().read(text).source)
        let asset = try #require(source.systemAssets.first)
        #expect(asset.description == "The card number and expiry a customer enters.")
    }
}
