import Testing
import ThreatModelKit
import TestSupport
import FileGateways

/// What a copy carries, field by field, and what a paste puts back.
@Suite("What a copy carries")
struct ClipboardCarriesAnswersTests {
    private let models = InMemoryThreatModelGateway()
    private let catalogue = CatalogueFixture.catalogue()
    private let ids = SequentialIdentityGenerator()
    private let codec = ThreatModelCodec()

    private let theft = ThreatId("credential-theft")

    /// One EC2 node with every field set, one link, one private zone, and an
    /// answer of each kind on all three.
    private func seed() -> ThreatModel {
        let component = Component(
            id: ComponentId("c1"),
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 100, y: 200),
            sensitivity: .confidential,
            customName: "Web tier",
            threatsDisabled: false,
            runsAs: .admin,
            assets: [Asset(name: "the card numbers", sensitivity: .restricted)],
            shape: .store
        )
        let other = Component(
            id: ComponentId("c2"),
            technologyId: TechnologyId("aws-rds"),
            position: Point(x: 500, y: 200),
            sensitivity: .restricted
        )
        let model = ThreatModel(
            name: "Payments",
            components: [component, other],
            connections: [
                Connection(
                    id: ConnectionId("k1"),
                    source: ComponentId("c1"),
                    target: ComponentId("c2"),
                    kind: .ipc,
                    description: "the card number goes over this link"
                )
            ],
            zones: [
                Zone(
                    id: ZoneId("z1"),
                    rect: Rect(x: 0, y: 0, width: 800, height: 700),
                    name: "Payments VPC",
                    networkZone: .privateZone,
                    networkType: .vpc,
                    riskReductionEnabled: true,
                    riskReductionPercent: 35,
                    boundary: .network,
                    description: "the zone the card data sits in"
                )
            ],
            severityOverrides: [
                SeverityOverrideKey.forComponent(componentId: ComponentId("c1"), threatId: theft): "low",
                SeverityOverrideKey.forConnection(threatId: ThreatId("connection-mitm")): "low",
                SeverityOverrideKey.forZone(threatId: ThreatId("lateral-movement")): "low"
            ],
            controlStatuses: [
                tickOnTheNode(): .implemented,
                tickOnEveryLink(): .implemented,
                tickOnEveryZone(): .implemented
            ],
            likelihoodFindings: [
                ThreatKey(threatId: theft.value, sourceId: "component:c1"): finding(),
                ThreatKey(threatId: "connection-mitm", sourceId: "connection:k1"): finding(),
                ThreatKey(threatId: "lateral-movement", sourceId: "zone:z1"): finding()
            ]
        )
        models.save(model)
        return model
    }

    private func finding() -> LikelihoodFinding {
        LikelihoodFinding(
            label: "the exploit is on sale",
            likelihood: .commodity,
            rationale: "two vendors sell it",
            sources: []
        )
    }

    private func tickOnTheNode() -> ControlKey {
        ControlIdentity.componentControl(
            componentId: ComponentId("c1"),
            threatId: theft,
            description: "Enforce IMDSv2 to block SSRF-based credential theft",
            isTechnologySpecific: true
        )
    }

    private func tickOnEveryLink() -> ControlKey {
        ControlIdentity.connectionControl(
            threatId: ThreatId("connection-mitm"),
            description: "Enforce TLS on every hop"
        )
    }

    private func tickOnEveryZone() -> ControlKey {
        ControlIdentity.zoneControl(
            threatId: ThreatId("lateral-movement"),
            description: "Segment the network and restrict east-west traffic"
        )
    }

    private func copiedSnippet(
        components: [String] = ["c1", "c2"],
        zones: [String] = ["z1"]
    ) -> SelectionSnippet {
        guard case .copied(let payload, _, _) = CopySelection(models: models, files: codec)
            .execute(CopySelectionRequest(componentIds: components, zoneIds: zones)) else {
            Issue.record("Expected the selection to be copied")
            return SelectionSnippet(components: [], connections: [], zones: [])
        }
        guard let read = try? codec.decodeSelection(payload) else {
            Issue.record("Expected the clipboard text to be read back")
            return SelectionSnippet(components: [], connections: [], zones: [])
        }
        return read
    }

    private func paste(
        _ payload: String,
        into catalogue: TechnologyCatalogue? = nil
    ) -> PasteSelectionResponse {
        PasteSelection(
            models: models,
            ids: ids,
            files: codec,
            catalogue: catalogue ?? self.catalogue
        ).execute(PasteSelectionRequest(payload: payload, offsetX: 40, offsetY: 40))
    }

    private func payload(components: [String] = ["c1", "c2"], zones: [String] = ["z1"]) -> String {
        guard case .copied(let payload, _, _) = CopySelection(models: models, files: codec)
            .execute(CopySelectionRequest(componentIds: components, zoneIds: zones)) else {
            Issue.record("Expected the selection to be copied")
            return ""
        }
        return payload
    }

    @Test func carriesEveryFieldOfAComponent() throws {
        let model = seed()

        let snippet = copiedSnippet()

        let copied = try #require(snippet.components.first { $0.id == ComponentId("c1") })
        let original = try #require(model.component(ComponentId("c1")))
        #expect(copied == original)
    }

    @Test func carriesEveryFieldOfALinkAndOfAZone() throws {
        let model = seed()

        let snippet = copiedSnippet()

        #expect(snippet.connections == model.connections)
        #expect(snippet.zones == model.zones)
    }

    @Test func carriesTheTicksTheOverridesAndTheFindings() {
        _ = seed()

        let snippet = copiedSnippet()

        #expect(snippet.controlStatuses.count == 3)
        #expect(snippet.controlStatuses[tickOnTheNode()] == .implemented)
        #expect(snippet.controlStatuses[tickOnEveryLink()] == .implemented)
        #expect(snippet.controlStatuses[tickOnEveryZone()] == .implemented)
        #expect(snippet.severityOverrides.count == 3)
        #expect(snippet.likelihoodFindings.count == 3)
    }

    @Test func carriesNoAnswerOfAnElementNobodyCopied() {
        _ = seed()

        // The node alone: no link and no zone came along, so the answers
        // consolidated across every link and every zone stay behind.
        let snippet = copiedSnippet(components: ["c1"], zones: [])

        #expect(snippet.controlStatuses == [tickOnTheNode(): .implemented])
        #expect(
            snippet.severityOverrides == [
                SeverityOverrideKey.forComponent(
                    componentId: ComponentId("c1"),
                    threatId: theft
                ): "low"
            ]
        )
        #expect(
            snippet.likelihoodFindings.keys.map(\.value)
                == ["\(theft.value)@component:c1"]
        )
    }

    @Test func putsEveryAnswerBackOnTheFreshIdentifiers() throws {
        _ = seed()
        let text = payload(components: ["c1"], zones: [])

        guard case .pasted(let componentIds, _, let dropped) = paste(text) else {
            Issue.record("Expected the selection to be pasted")
            return
        }

        #expect(dropped.isEmpty)
        let fresh = ComponentId(try #require(componentIds.first))
        let model = models.current()
        #expect(
            model.controlStatuses[
                ControlIdentity.componentControl(
                    componentId: fresh,
                    threatId: theft,
                    description: "Enforce IMDSv2 to block SSRF-based credential theft",
                    isTechnologySpecific: true
                )
            ] == .implemented
        )
        #expect(
            model.severityOverrides[
                SeverityOverrideKey.forComponent(componentId: fresh, threatId: theft)
            ] == "low"
        )
        #expect(
            model.likelihoodFindings[
                ThreatKey(threatId: theft.value, sourceId: "component:\(fresh.value)")
            ] == finding()
        )
    }

    @Test func scoresThePastedElementTheSameAsTheCopiedOne() throws {
        _ = seed()
        let text = payload(components: ["c1"], zones: [])

        guard case .pasted(let componentIds, _, _) = paste(text) else {
            Issue.record("Expected the selection to be pasted")
            return
        }
        let fresh = try #require(componentIds.first)

        let response = AssessThreatModel(models: models, catalogue: catalogue)
            .execute(AssessThreatModelRequest())
        let original = response.threats
            .filter { $0.source.id == "component:c1" }
            .sorted { $0.threatId < $1.threatId }
        let pasted = response.threats
            .filter { $0.source.id == "component:\(fresh)" }
            .sorted { $0.threatId < $1.threatId }

        #expect(original.isEmpty == false)
        #expect(pasted.map(\.threatId) == original.map(\.threatId))
        #expect(pasted.map(\.riskScore) == original.map(\.riskScore))
        #expect(pasted.map(\.severityId) == original.map(\.severityId))
    }

    @Test func statesWhatItDroppedWhenTheCatalogueWordsNoSuchControl() throws {
        _ = seed()
        let text = payload(components: ["c1"], zones: [])

        // The same technology, with every control reworded, so the answer the
        // copy carries reaches nothing.
        let reworded = InMemoryTechnologyCatalogue(
            technologies: [
                Technology(
                    id: TechnologyId("aws-ec2"),
                    name: "EC2",
                    provider: ProviderId("aws"),
                    category: CategoryId("compute"),
                    description: "",
                    threatIds: [theft]
                )
            ],
            threats: [
                Threat(
                    id: theft,
                    name: "Credential Theft",
                    description: "",
                    severity: CatalogueFixture.critical,
                    controls: [Control(id: "ctrl-1", description: "Some other wording entirely")]
                )
            ] + CatalogueFixture.connectionThreats() + CatalogueFixture.zoneThreats(),
            taxonomy: CatalogueFixture.taxonomy(),
            providers: CatalogueFixture.providers()
        )

        guard case .pasted(_, _, let dropped) = paste(text, into: reworded) else {
            Issue.record("Expected the selection to be pasted")
            return
        }

        #expect(dropped.count == 1)
        let droppedKey = try #require(dropped.first)
        #expect(droppedKey.contains("credential-theft"))
        // The element itself still arrives: a dropped answer is not a dropped
        // component.
        #expect(models.current().components.count == 3)
    }

    @Test func leavesAnAnswerTheModelAlreadyHoldsAlone() {
        _ = seed()
        let text = payload(components: ["c1", "c2"], zones: ["z1"])

        _ = paste(text)

        // The link answer and the zone answer are consolidated across the
        // model, so the paste reads them onto keys that are already there.
        #expect(models.current().controlStatuses[tickOnEveryLink()] == .implemented)
        #expect(models.current().controlStatuses[tickOnEveryZone()] == .implemented)
        #expect(
            models.current().severityOverrides[
                SeverityOverrideKey.forConnection(threatId: ThreatId("connection-mitm"))
            ] == "low"
        )
    }

    @Test func pastesEveryAnswerAsOneStepToTakeBack() {
        let before = seed()
        let text = payload(components: ["c1"], zones: [])

        _ = paste(text)
        #expect(models.current() != before)

        if case .nothingToUndo = UndoLastChange(models: models).execute(UndoLastChangeRequest()) {
            Issue.record("Expected the paste to be taken back")
        }
        #expect(models.current() == before)
    }

    @Test func carriesTheAnswersThroughADuplicateToo() throws {
        _ = seed()

        guard case .duplicated(let componentIds, _) = DuplicateSelection(
            models: models,
            ids: ids,
            catalogue: catalogue
        ).execute(
            DuplicateSelectionRequest(componentIds: ["c1"], zoneIds: [], offsetX: 40, offsetY: 40)
        ) else {
            Issue.record("Expected the selection to be duplicated")
            return
        }

        let fresh = ComponentId(try #require(componentIds.first))
        #expect(
            models.current().severityOverrides[
                SeverityOverrideKey.forComponent(componentId: fresh, threatId: theft)
            ] == "low"
        )
    }
}
