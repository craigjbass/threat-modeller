import ArchitectureDSL
import Foundation
import SwiftUI
import Testing
import ThreatModelKit
import TestSupport
@testable import threatmodeller

/// The System menu, the toolbar control beside it, and the seven sheets they
/// open.
///
/// Each test runs the row from the menu, runs the same row from the toolbar,
/// writes one entry through the button the sheet draws, saves, and reads the
/// `.arch` file back.
@MainActor
@Suite("The System menu and its sheets")
struct SystemMenuFlowTests {
    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }
    }

    """

    private func aProject(_ text: String? = nil) async -> (ProjectSession, TestDependencies) {
        let useCases = TestDependencies()
        useCases.project.put(text ?? payments, at: "/work/threatmodel/payments.arch")
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

    private func written(_ useCases: TestDependencies) throws -> ArchitectureSource {
        let text = try #require(architecture(useCases))
        return try #require(HclArchitectureSource().read(text).source)
    }

    /// Runs the row with this identifier, wherever the rows came from.
    private func run(_ rows: [ElementMenu.Row], _ id: String) {
        for row in rows {
            if case .item(let rowId, _, _, _, let act) = row, rowId == id { act() }
        }
    }

    /// Opens one sheet from the menu bar, closes it, and opens it again from
    /// the toolbar. Both paths draw the same rows, and both must set the
    /// sheet the window then presents.
    private func openFromBothControls(_ kind: SystemSheetKind, _ project: ProjectSession) {
        let id = SystemMenu.rowId(of: kind)

        run(ThreatModelCommands.systemRows(project: project), id)
        #expect(project.systemSheet == kind, "the menu bar did not open \(kind.title)")

        project.systemSheet = nil
        run(ProjectWindow.systemRows(project: project), id)
        #expect(project.systemSheet == kind, "the toolbar did not open \(kind.title)")
    }

    // MARK: Document Control

    @Test func opensDocumentControlAndWritesOneAttribute() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)
        openFromBothControls(.documentControl, project)

        let sheet = DocumentControlSheet(
            session: model,
            dismiss: {},
            draft: .init(name: "service_tier", value: "gold")
        )
        sheet.write()
        model.setSystemFacts(owner: "Payments team")
        await project.save()

        #expect(model.errorMessage == nil)
        let source = try written(useCases)
        #expect(source.owner == "Payments team")
        #expect(source.attributes.map(\.name) == ["service_tier"])
        #expect(source.attributes.map(\.value) == ["gold"])
    }

    @Test func aSecondWriteOfTheSameAttributeNameChangesTheAttributeThatIsThere() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)
        model.setSystemFacts(owner: "Payments team")

        let first = DocumentControlSheet(
            session: model,
            dismiss: {},
            draft: .init(name: "service_tier", value: "gold")
        )
        first.write()
        let other = DocumentControlSheet(
            session: model,
            dismiss: {},
            draft: .init(name: "cost_centre", value: "1234")
        )
        other.write()
        let second = DocumentControlSheet(
            session: model,
            dismiss: {},
            draft: .init(name: "service_tier", value: "silver")
        )
        second.write()
        await project.save()

        #expect(model.errorMessage == nil)
        let source = try written(useCases)
        #expect(source.attributes.map(\.name) == ["service_tier", "cost_centre"])
        #expect(source.attributes.map(\.value) == ["silver", "1234"])
        #expect(source.owner == "Payments team")
        #expect(source.systemName == "Payments")
        #expect(source.components.map(\.id) == ["api"])
    }

    // MARK: Assets

    @Test func opensAssetsAndWritesOneAsset() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)
        openFromBothControls(.assets, project)

        let sheet = AssetsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: "card-data",
                name: "Card data",
                classification: "confidential",
                description: "The card number and expiry a customer enters.",
                owner: "Payments team"
            )
        )
        sheet.write()
        await project.save()

        #expect(model.errorMessage == nil)
        let asset = try #require(try written(useCases).systemAssets.first)
        #expect(asset.id == "card-data")
        #expect(asset.name == "Card data")
        #expect(asset.classification == "confidential")
        #expect(asset.description == "The card number and expiry a customer enters.")
        #expect(asset.owner == "Payments team")
    }

    @Test func aSecondWriteOfTheSameAssetIdentifierChangesTheAssetThatIsThere() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)

        let first = AssetsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: "card-data",
                name: "Card data",
                classification: "confidential",
                description: "The card number a customer enters.",
                owner: "Payments team"
            )
        )
        first.write()
        let other = AssetsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: "audit-log",
                name: "Audit log",
                classification: "internal",
                description: "What the service wrote down.",
                owner: "Platform team"
            )
        )
        other.write()
        let second = AssetsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: "card-data",
                name: "Card number",
                classification: "restricted",
                description: "The card number and the expiry.",
                owner: "Card team"
            )
        )
        second.write()
        await project.save()

        #expect(model.errorMessage == nil)
        let source = try written(useCases)
        #expect(source.systemAssets.map(\.id) == ["card-data", "audit-log"])
        let changed = try #require(source.systemAssets.first)
        #expect(changed.name == "Card number")
        #expect(changed.classification == "restricted")
        #expect(changed.description == "The card number and the expiry.")
        #expect(changed.owner == "Card team")
        #expect(source.systemAssets.last?.name == "Audit log")
        #expect(source.systemAssets.last?.classification == "internal")
        #expect(source.systemName == "Payments")
        #expect(source.components.map(\.id) == ["api"])
    }

    // MARK: Third parties

    @Test func opensThirdPartiesAndWritesOneParty() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)
        openFromBothControls(.thirdParties, project)

        let sheet = ThirdPartiesSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: "stripe",
                name: "Stripe",
                description: "Takes the card payments.",
                kind: "saas",
                pays: true,
                uptime: "hard",
                uptimeNotes: "No payment runs while Stripe is down.",
                owner: "Payments team",
                link: "https://stripe.com"
            )
        )
        sheet.write()
        await project.save()

        #expect(model.errorMessage == nil)
        let party = try #require(try written(useCases).thirdParties.first)
        #expect(party.id == "stripe")
        #expect(party.name == "Stripe")
        #expect(party.kind == "saas")
        #expect(party.payingCustomer)
        #expect(party.uptime == "hard")
        #expect(party.owner == "Payments team")
        #expect(party.link == "https://stripe.com")
    }

    // MARK: Use cases

    @Test func opensUseCasesAndWritesOneUseCase() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)
        openFromBothControls(.useCases, project)

        let sheet = UseCasesSheet(
            session: model,
            dismiss: {},
            draft: .init(label: "Pay by card", text: "A customer pays with a card.")
        )
        sheet.write()
        await project.save()

        #expect(model.errorMessage == nil)
        let useCase = try #require(try written(useCases).useCases.first)
        #expect(useCase.label == "Pay by card")
        #expect(useCase.text == "A customer pays with a card.")
    }

    @Test func aSecondWriteOfTheSameUseCaseLabelChangesTheUseCaseThatIsThere() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)

        let first = UseCasesSheet(
            session: model,
            dismiss: {},
            draft: .init(label: "Pay by card", text: "A customer pays with a card.")
        )
        first.write()
        let other = UseCasesSheet(
            session: model,
            dismiss: {},
            draft: .init(label: "Refund", text: "An agent refunds a payment.")
        )
        other.write()
        let second = UseCasesSheet(
            session: model,
            dismiss: {},
            draft: .init(label: "Pay by card", text: "A customer pays with a saved card.")
        )
        second.write()
        await project.save()

        #expect(model.errorMessage == nil)
        let source = try written(useCases)
        #expect(source.useCases.map(\.label) == ["Pay by card", "Refund"])
        #expect(source.useCases.first?.text == "A customer pays with a saved card.")
        #expect(source.useCases.last?.text == "An agent refunds a payment.")
        #expect(source.systemName == "Payments")
        #expect(source.components.map(\.id) == ["api"])
    }

    // MARK: Exclusions

    @Test func opensExclusionsAndWritesOneExclusion() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)
        openFromBothControls(.exclusions, project)

        let sheet = ExclusionsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                label: "The card network",
                text: "The card network is not modelled.",
                rationale: "Another team owns it."
            )
        )
        sheet.write()
        await project.save()

        #expect(model.errorMessage == nil)
        let exclusion = try #require(try written(useCases).exclusions.first)
        #expect(exclusion.label == "The card network")
        #expect(exclusion.text == "The card network is not modelled.")
        #expect(exclusion.rationale == "Another team owns it.")
    }

    @Test func aSecondWriteOfTheSameExclusionLabelChangesTheExclusionThatIsThere() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)

        let first = ExclusionsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                label: "The card network",
                text: "The card network is not modelled.",
                rationale: "Another team owns it."
            )
        )
        first.write()
        let other = ExclusionsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                label: "The office network",
                text: "The office network is not modelled.",
                rationale: "The IT team owns it."
            )
        )
        other.write()
        let second = ExclusionsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                label: "The card network",
                text: "The card network stays outside this model.",
                rationale: "The card scheme states its own model."
            )
        )
        second.write()
        await project.save()

        #expect(model.errorMessage == nil)
        let source = try written(useCases)
        #expect(source.exclusions.map(\.label) == ["The card network", "The office network"])
        let changed = try #require(source.exclusions.first)
        #expect(changed.text == "The card network stays outside this model.")
        #expect(changed.rationale == "The card scheme states its own model.")
        #expect(source.exclusions.last?.rationale == "The IT team owns it.")
        #expect(source.systemName == "Payments")
        #expect(source.components.map(\.id) == ["api"])
    }

    // MARK: Diagrams

    @Test func opensDiagramsAndWritesOneDiagram() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)
        openFromBothControls(.diagrams, project)

        let sheet = DiagramsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                label: "The login sequence",
                kind: "d2",
                text: "sequenceDiagram\n  Customer->>API: signs in"
            )
        )
        sheet.write()
        await project.save()

        #expect(model.errorMessage == nil)
        let diagram = try #require(try written(useCases).diagrams.first)
        #expect(diagram.label == "The login sequence")
        #expect(diagram.kind == "d2")
        #expect(diagram.text.contains("sequenceDiagram"))
    }

    // MARK: Threat actors

    @Test func opensThreatActorsAndWritesOneActor() async throws {
        let (project, useCases) = await aProject()
        let model = try #require(project.model)
        openFromBothControls(.threatActors, project)

        let sheet = ThreatActorsSheet(
            session: model,
            dismiss: {},
            draft: .init(
                id: "contractor",
                name: "Third-party contractor",
                description: "Somebody who works on this system and is not on the team.",
                capability: "targeted",
                intent: "money",
                performs: "credential-theft"
            )
        )
        sheet.write()
        model.setFacedThreatActors(["contractor"])
        await project.save()

        #expect(model.errorMessage == nil)
        let source = try written(useCases)
        let actor = try #require(source.threatActors.first)
        #expect(actor.id == "contractor")
        #expect(actor.name == "Third-party contractor")
        #expect(source.faces == ["contractor"])
    }

    // MARK: the badges

    @Test func theBadgesEqualTheCountsTheModelHolds() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)

        for kind in SystemSheetKind.allCases {
            #expect(kind.badge(in: model) == "\u{2014}", "\(kind.title) badges a count with nothing written")
        }

        model.setSystemAttribute(name: "service_tier", value: "gold")
        model.setSystemAsset(id: "card-data", name: "Card data", classificationId: "confidential")
        model.setThirdParty(
            id: "stripe",
            name: "Stripe",
            description: "Takes the card payments.",
            kindId: "saas",
            payingCustomer: true,
            uptimeId: "hard",
            uptimeNotes: "",
            owner: nil,
            link: nil
        )
        model.setSystemUseCase(label: "Pay by card", text: "A customer pays with a card.")
        model.setExclusion(
            label: "The card network",
            text: "The card network is not modelled.",
            rationale: "Another team owns it."
        )
        model.setSystemDiagram(label: "The login sequence", text: "sequenceDiagram")
        model.setLocalThreatActor(
            id: "contractor",
            name: "Third-party contractor",
            capability: "targeted",
            performs: ["credential-theft"]
        )
        model.setFacedThreatActors(["contractor"])

        #expect(SystemSheetKind.documentControl.badge(in: model) == "1")
        #expect(SystemSheetKind.assets.badge(in: model) == "1")
        #expect(SystemSheetKind.thirdParties.badge(in: model) == "1")
        #expect(SystemSheetKind.useCases.badge(in: model) == "1")
        #expect(SystemSheetKind.exclusions.badge(in: model) == "1")
        #expect(SystemSheetKind.diagrams.badge(in: model) == "1")
        #expect(SystemSheetKind.threatActors.badge(in: model) == "1")

        // The document control badge counts the named fields too.
        model.setSystemFacts(owner: "Payments team", version: "1.2")
        #expect(SystemSheetKind.documentControl.badge(in: model) == "3")
    }

    @Test func everyRowNamesItsSheetAndCarriesItsBadge() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)
        model.setSystemUseCase(label: "Pay by card", text: "A customer pays with a card.")

        let rows = ThreatModelCommands.systemRows(project: project)

        #expect(rows.map(\.id) == SystemSheetKind.allCases.map(SystemMenu.rowId(of:)))
        #expect(rows.map(\.title).contains { $0.hasPrefix("Use Cases") && $0.hasSuffix("1") })
        #expect(rows.map(\.title).contains { $0.hasPrefix("Assets") && $0.hasSuffix("\u{2014}") })
    }

    /// Every row is off while the window draws no system, because a sheet
    /// with no model has nothing to write into.
    @Test func everyRowIsOffWhileNoSystemIsDrawn() async {
        let useCases = TestDependencies()
        let project = ProjectSession(
            useCases: useCases,
            watcher: FakeProjectWatcher(),
            defaults: aTestDefaults()
        )

        for row in SystemMenu(project: project).rows {
            guard case .item(let id, _, _, let isEnabled, _) = row else { continue }
            #expect(isEnabled == false, "\(id) is on with no system drawn")
        }
    }

    // MARK: the sheets draw

    @Test func everySheetDraws() async throws {
        let (project, _) = await aProject()
        let model = try #require(project.model)

        for kind in SystemSheetKind.allCases {
            let renderer = ImageRenderer(
                content: SystemSheetView(kind: kind, session: model, dismiss: {})
                    .frame(width: 900, height: 600)
            )
            renderer.scale = 1
            #expect(renderer.cgImage != nil, "\(kind.title) drew nothing")
        }
    }
}
