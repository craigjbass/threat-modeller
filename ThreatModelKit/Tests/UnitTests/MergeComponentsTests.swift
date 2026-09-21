import ArchitectureDSL
import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// Merging two or more components into one, as
/// `docs/superpowers/specs/2026-09-16-merge-components-design.md` decides.
@Suite("Merging components")
struct MergeComponentsTests {
    private static let control = "Enforce IMDSv2 to block SSRF-based credential theft"

    // MARK: fixtures

    private static func component(
        _ id: String,
        technology: String = "aws-ec2",
        zone: String? = nil,
        assets: [Asset] = []
    ) -> Component {
        Component(
            id: ComponentId(id),
            technologyId: TechnologyId(technology),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData,
            assets: assets,
            zoneId: zone.map(ZoneId.init)
        )
    }

    private static func flow(
        _ id: String,
        _ source: String,
        _ target: String,
        kind: FlowKind = .default,
        description: String? = nil,
        carries: [String] = [],
        tags: [String] = []
    ) -> Connection {
        Connection(
            id: ConnectionId(id),
            source: ComponentId(source),
            target: ComponentId(target),
            kind: kind,
            description: description,
            carries: carries,
            tags: tags
        )
    }

    private func aModel(_ model: ThreatModel) -> TestDependencies {
        let app = TestDependencies()
        app.modelStore.save(model)
        return app
    }

    private func merge(
        _ app: TestDependencies,
        survivor: String = "api",
        sources: [String] = ["api2"],
        technology: String = "aws-ec2",
        shape: String? = nil,
        name: String? = nil,
        sensitivity: String = "confidential",
        runsAs: String = "user",
        holds: [String] = [],
        zone: String? = nil,
        status: String = "live",
        tags: [String] = [],
        providedBy: String? = nil,
        root: String? = nil,
        systemName: String? = nil
    ) -> MergeComponentsResponse {
        app.mergeComponents().execute(
            MergeComponentsRequest(
                root: root,
                systemName: systemName,
                survivorId: survivor,
                sourceIds: sources,
                technologyId: technology,
                shape: shape,
                name: name,
                sensitivity: sensitivity,
                runsAs: runsAs,
                holds: holds,
                zoneId: zone,
                status: status,
                tags: tags,
                providedBy: providedBy
            )
        )
    }

    private func merged(_ response: MergeComponentsResponse) -> MergeComponentsResponse.Merged? {
        guard case .merged(let merged) = response else { return nil }
        return merged
    }

    // MARK: what is refused

    @Test func refusesAMergeWithNoSource() {
        let app = aModel(ThreatModel(components: [Self.component("api")]))

        #expect(merge(app, sources: []) == .tooFewComponents)
    }

    @Test func refusesAComponentTheModelDoesNotHold() {
        let app = aModel(ThreatModel(components: [Self.component("api")]))

        #expect(merge(app, sources: ["ghost"]) == .unknownComponent(componentId: "ghost"))
        #expect(merge(app, survivor: "ghost", sources: ["api"]) == .unknownComponent(componentId: "ghost"))
    }

    @Test func refusesASurvivorNamedAsASource() {
        let app = aModel(ThreatModel(components: [Self.component("api"), Self.component("api2")]))

        #expect(merge(app, sources: ["api", "api2"]) == .unknownComponent(componentId: "api"))
    }

    @Test func refusesAUser() {
        var alice = Self.component("alice")
        alice.user = UserFacts()
        let app = aModel(ThreatModel(components: [Self.component("api"), alice]))

        #expect(merge(app, sources: ["alice"]) == .userCannotMerge(componentId: "alice"))
    }

    @Test func refusesAWordTheVocabularyDoesNotHold() {
        let app = aModel(ThreatModel(components: [Self.component("api"), Self.component("api2")]))

        #expect(merge(app, technology: "not-a-technology") == .unknownTechnology)
        #expect(merge(app, shape: "blob") == .unknownShape)
        #expect(merge(app, sensitivity: "secret") == .unknownSensitivity)
        #expect(merge(app, runsAs: "god") == .unknownPrivilegeLevel)
        #expect(merge(app, holds: ["ghost"]) == .unknownAsset)
        #expect(merge(app, zone: "nowhere") == .unknownZone)
        #expect(merge(app, status: "maybe") == .unknownStatus)
        #expect(merge(app, providedBy: "nobody") == .unknownThirdParty)
        #expect(app.modelStore.current().components.count == 2)
        #expect(app.modelStore.canUndo == false)
    }

    // MARK: the survivor

    @Test func theSurvivorTakesTheResolvedAttributesAndTheSourcesLeave() throws {
        let app = aModel(
            ThreatModel(
                components: [Self.component("api"), Self.component("api2"), Self.component("api3")],
                zones: [Zone(id: ZoneId("edge"), rect: Rect(x: 0, y: 0, width: 400, height: 300))],
                systemAssets: [SystemAsset(id: "cards", name: "Cards")],
                thirdParties: [ThirdParty(id: "acme", name: "Acme")]
            )
        )

        let response = merge(
            app,
            sources: ["api2", "api3"],
            technology: "aws-rds",
            shape: "store",
            name: "The API",
            sensitivity: "restricted",
            runsAs: "admin",
            holds: ["cards"],
            zone: "edge",
            status: "proposed",
            tags: ["core"],
            providedBy: "acme"
        )

        #expect(merged(response) != nil)
        let model = app.modelStore.current()
        #expect(model.components.map(\.id.value) == ["api"])
        let api = try #require(model.component(ComponentId("api")))
        #expect(api.technologyId == TechnologyId("aws-rds"))
        #expect(api.shape == .store)
        #expect(api.customName == "The API")
        #expect(api.sensitivity == .restricted)
        #expect(api.runsAs == .admin)
        #expect(api.holds == ["cards"])
        #expect(api.zoneId == ZoneId("edge"))
        #expect(api.status == .proposed)
        #expect(api.tags == ["core"])
        #expect(api.providedBy == "acme")
    }

    @Test func aSourcesAssetJoinsTheSurvivorWhenTheSurvivorDoesNotHoldItsName() throws {
        let app = aModel(
            ThreatModel(components: [
                Self.component("api", assets: [Asset(name: "tokens", sensitivity: .internalData)]),
                Self.component(
                    "api2",
                    assets: [
                        Asset(name: "tokens", sensitivity: .restricted),
                        Asset(name: "logs", sensitivity: .internalData)
                    ]
                )
            ])
        )

        _ = merge(app)

        let api = try #require(app.modelStore.current().component(ComponentId("api")))
        #expect(api.assets.map(\.name) == ["tokens", "logs"])
        #expect(api.assets.first?.sensitivity == .internalData)
    }

    // MARK: the flows

    @Test func everyFlowOfASourceMovesToTheSurvivor() throws {
        let app = aModel(
            ThreatModel(
                components: [Self.component("api"), Self.component("api2"), Self.component("db"), Self.component("cdn")],
                connections: [
                    Self.flow("api2->db", "api2", "db", kind: .file, description: "writes"),
                    Self.flow("k1", "cdn", "api2")
                ]
            )
        )

        let response = merge(app)

        let outcome = try #require(merged(response))
        #expect(outcome.droppedFlowIds.isEmpty)
        #expect(outcome.joinedFlowIds.isEmpty)
        let flows = app.modelStore.current().connections
        #expect(flows.map(\.id.value) == ["api->db", "k1"])
        #expect(flows[0].source == ComponentId("api"))
        #expect(flows[0].target == ComponentId("db"))
        #expect(flows[0].kind == .file)
        #expect(flows[0].description == "writes")
        #expect(flows[1].source == ComponentId("cdn"))
        #expect(flows[1].target == ComponentId("api"))
    }

    @Test func aFlowBetweenTwoSourcesOrASourceAndTheSurvivorIsDropped() throws {
        let app = aModel(
            ThreatModel(
                components: [Self.component("api"), Self.component("api2"), Self.component("api3")],
                connections: [
                    Self.flow("api->api2", "api", "api2"),
                    Self.flow("api2->api3", "api2", "api3"),
                    Self.flow("api3->api", "api3", "api")
                ]
            )
        )

        let response = merge(app, sources: ["api2", "api3"])

        let outcome = try #require(merged(response))
        #expect(outcome.droppedFlowIds == ["api->api2", "api2->api3", "api3->api"])
        #expect(app.modelStore.current().connections.isEmpty)
    }

    @Test func aDuplicateFlowJoinsIntoTheFirstWithTheUnionOfCarriesAndTags() throws {
        let app = aModel(
            ThreatModel(
                components: [Self.component("api"), Self.component("api2"), Self.component("db")],
                connections: [
                    Self.flow("api->db", "api", "db", kind: .network, description: "reads", carries: ["cards"], tags: ["core"]),
                    Self.flow("api2->db", "api2", "db", kind: .ipc, description: "writes", carries: ["cards", "logs"], tags: ["batch"]),
                    Self.flow("db->api2", "db", "api2")
                ]
            )
        )

        let response = merge(app)

        let outcome = try #require(merged(response))
        #expect(outcome.joinedFlowIds == ["api2->db"])
        #expect(outcome.droppedFlowIds.isEmpty)
        let flows = app.modelStore.current().connections
        #expect(flows.map(\.id.value) == ["api->db", "db->api"])
        #expect(flows[0].kind == .network)
        #expect(flows[0].description == "reads")
        #expect(flows[0].carries == ["cards", "logs"])
        #expect(flows[0].tags == ["core", "batch"])
    }

    @Test func aMovedFlowThatJoinsAnotherDropsTheAnswerTheStayedFlowHolds() throws {
        let finding = LikelihoodFinding(label: "seen", likelihood: .targeted, rationale: "seen once")
        let app = aModel(
            ThreatModel(
                components: [Self.component("api"), Self.component("api2"), Self.component("db")],
                connections: [
                    Self.flow("api->db", "api", "db"),
                    Self.flow("api2->db", "api2", "db")
                ],
                likelihoodFindings: [
                    ThreatKey(threatId: "connection-mitm", sourceId: "connection:api->db"): finding,
                    ThreatKey(threatId: "connection-mitm", sourceId: "connection:api2->db"):
                        LikelihoodFinding(label: "never", likelihood: .research, rationale: "never seen"),
                    ThreatKey(threatId: "connection-dos", sourceId: "connection:api2->db"): finding
                ]
            )
        )

        let response = merge(app)

        let outcome = try #require(merged(response))
        #expect(outcome.droppedAnswers == ["connection-mitm@connection:api2->db"])
        let findings = app.modelStore.current().likelihoodFindings
        #expect(findings[ThreatKey(threatId: "connection-mitm", sourceId: "connection:api->db")] == finding)
        #expect(findings[ThreatKey(threatId: "connection-dos", sourceId: "connection:api->db")] == finding)
        #expect(findings.count == 2)
    }

    // MARK: the edges and the users

    @Test func mitigatesEdgesFollowTheFlowRules() {
        let app = aModel(
            ThreatModel(
                components: [Self.component("api"), Self.component("api2"), Self.component("waf")],
                mitigatesEdges: [
                    MitigatesEdge(
                        source: ComponentId("waf"),
                        target: ComponentId("api"),
                    ),
                    MitigatesEdge(
                        source: ComponentId("waf"),
                        target: ComponentId("api2"),
                    ),
                    MitigatesEdge(
                        source: ComponentId("api2"),
                        target: ComponentId("api"),
                    )
                ]
            )
        )

        _ = merge(app)

        let edges = app.modelStore.current().mitigatesEdges
        #expect(edges.count == 1)
        #expect(edges.first?.source == ComponentId("waf"))
        #expect(edges.first?.target == ComponentId("api"))
    }

    @Test func aUsersReachesNameTheSurvivorOnce() throws {
        var alice = Self.component("alice")
        alice.user = UserFacts(reaches: ["api", "api2", "db"])
        let app = aModel(
            ThreatModel(components: [Self.component("api"), Self.component("api2"), Self.component("db"), alice])
        )

        _ = merge(app)

        let user = try #require(app.modelStore.current().component(ComponentId("alice"))?.user)
        #expect(user.reaches == ["api", "db"])
    }

    // MARK: the answers in the model

    @Test func everyAnswerKeyedOnASourceMovesToTheSurvivor() throws {
        let statusKey = ControlIdentity.componentControl(
            componentId: ComponentId("api2"), threatId: ThreatId("credential-theft"), description: Self.control, isTechnologySpecific: true
        )
        let movedStatusKey = ControlIdentity.componentControl(
            componentId: ComponentId("api"), threatId: ThreatId("credential-theft"), description: Self.control, isTechnologySpecific: true
        )
        let proof = ControlProof(evidence: .tested, reference: "ci")
        let compensating = CompensatingControl(label: "WAF", reducesRiskBy: 20, rationale: "blocks it")
        let decision = SeverityDecision(severityId: "low", rationale: "internal only")
        let finding = LikelihoodFinding(label: "seen", likelihood: .targeted, rationale: "seen once")
        let recommendation = Recommendation(text: "Rotate")
        let app = aModel(
            ThreatModel(
                components: [Self.component("api"), Self.component("api2")],
                severityOverrides: [
                    SeverityOverrideKey.forComponent(componentId: ComponentId("api2"), threatId: ThreatId("dos-attack")): "low"
                ],
                controlStatuses: [statusKey: .implemented],
                compensatingControls: [ThreatKey(threatId: "credential-theft", sourceId: "component:api2"): [compensating]],
                recommendations: [ThreatKey(threatId: "misconfiguration", sourceId: "component:api2"): [recommendation]],
                likelihoodFindings: [ThreatKey(threatId: "credential-theft", sourceId: "component:api2"): finding],
                severityDecisions: [ThreatKey(threatId: "dos-attack", sourceId: "component:api2"): decision],
                impactOverrides: [ThreatKey(threatId: "misconfiguration", sourceId: "component:api2"): [.integrity]],
                controlProofs: [statusKey: proof]
            )
        )

        let response = merge(app)

        #expect(merged(response)?.droppedAnswers == [])
        let model = app.modelStore.current()
        #expect(model.controlStatuses == [movedStatusKey: .implemented])
        #expect(model.controlProofs == [movedStatusKey: proof])
        #expect(model.severityOverrides == [
            SeverityOverrideKey.forComponent(componentId: ComponentId("api"), threatId: ThreatId("dos-attack")): "low"
        ])
        #expect(model.compensatingControls == [ThreatKey(threatId: "credential-theft", sourceId: "component:api"): [compensating]])
        #expect(model.recommendations == [ThreatKey(threatId: "misconfiguration", sourceId: "component:api"): [recommendation]])
        #expect(model.likelihoodFindings == [ThreatKey(threatId: "credential-theft", sourceId: "component:api"): finding])
        #expect(model.severityDecisions == [ThreatKey(threatId: "dos-attack", sourceId: "component:api"): decision])
        #expect(model.impactOverrides == [ThreatKey(threatId: "misconfiguration", sourceId: "component:api"): [.integrity]])
    }

    @Test func anAnswerTheSurvivorAlreadyHoldsWinsAndTheSourcesIsReported() throws {
        let survivorKey = ControlIdentity.componentControl(
            componentId: ComponentId("api"), threatId: ThreatId("credential-theft"), description: Self.control, isTechnologySpecific: true
        )
        let sourceKey = ControlIdentity.componentControl(
            componentId: ComponentId("api2"), threatId: ThreatId("credential-theft"), description: Self.control, isTechnologySpecific: true
        )
        let kept = SeverityDecision(severityId: "low", rationale: "kept")
        let app = aModel(
            ThreatModel(
                components: [Self.component("api"), Self.component("api2")],
                controlStatuses: [survivorKey: .implemented, sourceKey: .notImplemented],
                severityDecisions: [
                    ThreatKey(threatId: "dos-attack", sourceId: "component:api"): kept,
                    ThreatKey(threatId: "dos-attack", sourceId: "component:api2"): SeverityDecision(severityId: "high", rationale: "dropped")
                ]
            )
        )

        let response = merge(app)

        #expect(merged(response)?.droppedAnswers == [
            "credential-theft@component:api2",
            "dos-attack@component:api2"
        ])
        let model = app.modelStore.current()
        #expect(model.controlStatuses == [survivorKey: .implemented])
        #expect(model.severityDecisions == [ThreatKey(threatId: "dos-attack", sourceId: "component:api"): kept])
    }

    @Test func anAnswerOnAThreatTheResolvedTechnologyDoesNotRaiseIsDropped() throws {
        let credentialKey = ControlIdentity.componentControl(
            componentId: ComponentId("api"), threatId: ThreatId("credential-theft"), description: Self.control, isTechnologySpecific: true
        )
        let misconfigurationKey = ControlIdentity.componentControl(
            componentId: ComponentId("api2"), threatId: ThreatId("misconfiguration"), description: "Scan configuration continuously", isTechnologySpecific: false
        )
        let app = aModel(
            ThreatModel(
                components: [Self.component("api"), Self.component("api2", technology: "aws-rds")],
                controlStatuses: [credentialKey: .implemented, misconfigurationKey: .implemented]
            )
        )

        let response = merge(app, technology: "aws-rds")

        #expect(merged(response)?.droppedAnswers == ["credential-theft@component:api"])
        let movedKey = ControlIdentity.componentControl(
            componentId: ComponentId("api"), threatId: ThreatId("misconfiguration"), description: "Scan configuration continuously", isTechnologySpecific: false
        )
        #expect(app.modelStore.current().controlStatuses == [movedKey: .implemented])
    }

    // MARK: the attack trees

    @Test func attackTreeGoalsAndStepsNameTheSurvivorAndTheMovedFlow() throws {
        let tree = SourceAttackTree(
            id: "read-cards",
            goal: SourceTreeTarget(threatId: "credential-theft", sourceKind: "component", sourceId: "api2"),
            root: .all([
                .step(SourceTreeStep(target: SourceTreeTarget(threatId: "connection-mitm", sourceKind: "flow", sourceId: "cdn->api2"))),
                .any([
                    .step(SourceTreeStep(target: SourceTreeTarget(threatId: "dos-attack", sourceKind: "component", sourceId: "api"), note: "stays")),
                    .step(SourceTreeStep(target: SourceTreeTarget(threatId: "connection-dos", sourceKind: "flow", sourceId: "api->api2")))
                ])
            ])
        )
        let app = aModel(
            ThreatModel(
                components: [Self.component("api"), Self.component("api2"), Self.component("cdn")],
                connections: [Self.flow("cdn->api2", "cdn", "api2"), Self.flow("api->api2", "api", "api2")],
                attackTrees: [tree]
            )
        )

        _ = merge(app)

        let rewritten = try #require(app.modelStore.current().attackTrees.first)
        #expect(rewritten.goal == SourceTreeTarget(threatId: "credential-theft", sourceKind: "component", sourceId: "api"))
        #expect(rewritten.steps.map(\.target.sourceId) == ["cdn->api", "api", "api->api2"])
        #expect(rewritten.steps[1].note == "stays")
    }

    // MARK: one undo

    @Test func theMergeIsOneUndoStep() {
        let before = ThreatModel(
            components: [Self.component("api"), Self.component("api2"), Self.component("db")],
            connections: [Self.flow("api2->db", "api2", "db"), Self.flow("api->db", "api", "db")],
            controlStatuses: [
                ControlIdentity.componentControl(
                    componentId: ComponentId("api2"), threatId: ThreatId("credential-theft"), description: Self.control, isTechnologySpecific: true
                ): .implemented
            ]
        )
        let app = aModel(before)

        _ = merge(app)
        #expect(app.modelStore.current() != before)

        let undone = app.undoLastChange().execute(UndoLastChangeRequest())

        #expect(undone == .undone(canUndoMore: false, label: "Merge Components"))
        #expect(app.modelStore.current() == before)
    }

    // MARK: the files

    private let payments = """
    system "Payments" {
      component "api" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "api2" {
        technology = "aws-ec2"
        data       = "confidential"
      }

      component "ledger" {
        technology = "aws-rds"
        data       = "restricted"
      }

      flow api -> ledger
      flow api2 -> ledger
    }

    """

    private let answered = """
    controls for "Payments" {
      tolerance = "high"

      threat "credential-theft" on component "api2" {
        severity = "critical"
        score    = 16

        likelihood "no campaign observed" {
          tier      = "research"
          rationale = "no known exploitation in the wild"
        }

        severity_override "low" {
          rationale = "internal only"
        }

        impacts = ["integrity"]

        control "Enforce IMDSv2 to block SSRF-based credential theft" {
          status      = "implemented"
          evidence    = "tested"
          reference   = "ci/imdsv2"
          verified_on = "2026-09-01"
        }

        compensating "WAF in front" {
          reduces_risk_by = 20
          rationale       = "blocks the SSRF"
        }

        recommendation "Rotate the role" {
          note = "quarterly"
        }
      }

      threat "misconfiguration" on component "api" {
        control "Scan configuration continuously" {
          status = "implemented"
        }
      }

      threat "misconfiguration" on component "api2" {
        control "Scan configuration continuously" {
          status = "accepted"
        }
      }

      threat "connection-mitm" on flow "api2->ledger" {
        control "Enforce TLS on every hop" {
          status = "implemented"
        }
      }

      threat "connection-mitm" on flow "api->ledger" {
        control "Enforce TLS on every hop" {
          status = "not_implemented"
        }
      }
    }

    """

    private let trees = """
    attack_trees for "Payments" {
      tree "read-cards" {
        goal "misconfiguration" on component "ledger"

        all_of {
          step "credential-theft" on component "api2"

          step "connection-mitm" on flow "api2->ledger"
        }
      }
    }

    """

    private let archPath = "/work/threatmodel/payments.arch"
    private let controlsPath = "/work/threatmodel/payments.controls"
    private let treePath = "/work/threatmodel/payments.attacktree"

    private func aProject(controls: String? = nil, trees: String? = nil) -> TestDependencies {
        let app = TestDependencies()
        app.project.put(payments, at: archPath)
        if let controls { app.project.put(controls, at: controlsPath) }
        if let trees { app.project.put(trees, at: treePath) }
        _ = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        return app
    }

    private func mergeTheProject(_ app: TestDependencies) -> MergeComponentsResponse {
        merge(app, root: "/work", systemName: "payments")
    }

    private func controlsSource(_ app: TestDependencies) throws -> ControlsSource {
        let text = try #require(app.project.text(at: controlsPath))
        return try #require(HclControlsSource().read(text).source)
    }

    @Test func theControlsFileMovesEveryStanzaOfASourceToTheSurvivor() throws {
        let app = aProject(controls: answered)

        let response = mergeTheProject(app)

        let outcome = try #require(merged(response))
        #expect(outcome.droppedAnswers == [
            "connection-mitm@connection:api2->ledger",
            "misconfiguration@component:api2"
        ])
        let source = try controlsSource(app)
        #expect(source.riskTolerance == "high")
        #expect(source.answers.map(\.key.value) == [
            "credential-theft@component:api",
            "misconfiguration@component:api",
            "connection-mitm@connection:api->ledger"
        ])
        let moved = try #require(source.answer(for: ThreatKey(threatId: "credential-theft", sourceId: "component:api")))
        #expect(moved.isStale == false)
        #expect(moved.likelihood?.label == "no campaign observed")
        #expect(moved.severityDecision?.severityId == "low")
        #expect(moved.impacts == ["integrity"])
        #expect(moved.controls.first?.status == .implemented)
        #expect(moved.controls.first?.proof.evidence == .tested)
        #expect(moved.compensating.first?.label == "WAF in front")
        #expect(moved.recommendations.first?.text == "Rotate the role")
        let kept = try #require(source.answer(for: ThreatKey(threatId: "misconfiguration", sourceId: "component:api")))
        #expect(kept.controls.first?.status == .implemented)
        let flow = try #require(source.answer(for: ThreatKey(threatId: "connection-mitm", sourceId: "connection:api->ledger")))
        #expect(flow.controls.first?.status == .notImplemented)
    }

    @Test func aControlsFileWithNoStanzaOnASourceIsNotWritten() {
        let untouched = """
        controls for "Payments" {
          threat "misconfiguration" on component "ledger" {
            control "Scan configuration continuously" {
              status = "implemented"
            }
          }
        }

        """
        let app = aProject(controls: untouched)

        _ = mergeTheProject(app)

        #expect(app.project.text(at: controlsPath) == untouched)
    }

    @Test func theRewrittenControlsFileRoundTripsThroughTheOneWriter() throws {
        let app = aProject(controls: answered)

        _ = mergeTheProject(app)

        let written = try #require(app.project.text(at: controlsPath))
        let gateway = HclControlsSource()
        let source = try #require(gateway.read(written).source)
        #expect(gateway.write(source) == written)
    }

    @Test func theAttackTreeFileNamesTheSurvivor() throws {
        let app = aProject(trees: trees)

        _ = mergeTheProject(app)

        let written = try #require(app.project.text(at: treePath))
        #expect(written == """
        attack_trees for "Payments" {
          tree "read-cards" {
            goal "misconfiguration" on component "ledger"

            all_of {
              step "credential-theft" on component "api"
              step "connection-mitm" on flow "api->ledger"
            }
          }
        }

        """)
    }

    @Test func theResponseCarriesTheBytesBeforeAndAfterAndTheSnapshotPutsThemBack() throws {
        let app = aProject(controls: answered, trees: trees)

        let response = mergeTheProject(app)

        let outcome = try #require(merged(response))
        #expect(outcome.filesBefore == [
            FileSnapshot(path: controlsPath, text: answered),
            FileSnapshot(path: treePath, text: trees)
        ])
        #expect(outcome.filesAfter.map(\.path) == [controlsPath, treePath])
        #expect(outcome.filesAfter[0].text == app.project.text(at: controlsPath))
        #expect(outcome.filesAfter[0].text != answered)

        let restored = app.restoreFileSnapshots().execute(
            RestoreFileSnapshotsRequest(snapshots: outcome.filesBefore)
        )

        #expect(restored == .restored)
        #expect(app.project.text(at: controlsPath) == answered)
        #expect(app.project.text(at: treePath) == trees)
    }

    @Test func aSnapshotThatReadNoFileDeletesTheFile() {
        let app = aProject(controls: answered)

        let restored = app.restoreFileSnapshots().execute(
            RestoreFileSnapshotsRequest(snapshots: [FileSnapshot(path: controlsPath, text: nil)])
        )

        #expect(restored == .restored)
        #expect(app.project.exists(path: controlsPath) == false)
    }

    @Test func aProjectWithNoControlsFileSnapshotsNothing() throws {
        let app = aProject()

        let response = mergeTheProject(app)

        let outcome = try #require(merged(response))
        #expect(outcome.filesBefore == [])
        #expect(outcome.filesAfter == [])
        #expect(app.project.exists(path: controlsPath) == false)
    }

    @Test func aModelWithNoRootChangesNoFile() {
        let app = aProject(controls: answered)

        let response = merge(app)

        #expect(merged(response)?.filesBefore == [])
        #expect(app.project.text(at: controlsPath) == answered)
        #expect(app.modelStore.current().components.map(\.id.value) == ["api", "ledger"])
    }

    @Test func refusesASystemTheProjectDoesNotHold() {
        let app = aProject(controls: answered)

        #expect(merge(app, root: "/work", systemName: "ghost") == .noSuchSystem)
        #expect(app.modelStore.current().components.count == 3)
    }

    // MARK: the golden

    private static let goldens = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Goldens")
        .appendingPathComponent("merge")

    private static func golden(_ name: String) throws -> String {
        try String(contentsOf: goldens.appendingPathComponent(name), encoding: .utf8)
    }

    private func aGoldenProject() throws -> TestDependencies {
        let app = TestDependencies()
        app.project.put(try Self.golden("before.arch"), at: archPath)
        app.project.put(try Self.golden("before.controls"), at: controlsPath)
        let opened = app.openSystem().execute(OpenSystemRequest(root: "/work", systemName: "payments"))
        #expect(opened == .opened(name: "Payments", warnings: []))
        return app
    }

    private func saveTheGoldenProject(_ app: TestDependencies) {
        _ = app.saveSystem().execute(SaveSystemRequest(root: "/work", systemName: "payments"))
        _ = app.saveSystemAnswers().execute(SaveSystemAnswersRequest(root: "/work", systemName: "payments"))
    }

    /// The golden project merges `api2` into `api`, keeps `api2`'s name and
    /// saves. The two files after the save are the bytes the goldens state.
    @Test func theGoldenMergeWritesTheStatedBytes() throws {
        let app = try aGoldenProject()

        let response = merge(
            app,
            name: "Payments API",
            sensitivity: "restricted",
            holds: ["cards"],
            zone: "app",
            tags: ["core", "edge"],
            root: "/work",
            systemName: "payments"
        )
        saveTheGoldenProject(app)

        #expect(merged(response) != nil)
        #expect(app.project.text(at: archPath) == (try Self.golden("after.arch")))
        #expect(app.project.text(at: controlsPath) == (try Self.golden("after.controls")))
    }

    /// Writes the golden files after a change a reader has agreed. It is not
    /// a test: set `THREATMODELLER_WRITE_GOLDENS=1` and run the suite.
    @Test func writesTheGoldenFilesWhenAskedTo() throws {
        guard ProcessInfo.processInfo.environment["THREATMODELLER_WRITE_GOLDENS"] == "1" else { return }
        let app = try aGoldenProject()
        _ = merge(
            app,
            name: "Payments API",
            sensitivity: "restricted",
            holds: ["cards"],
            zone: "app",
            tags: ["core", "edge"],
            root: "/work",
            systemName: "payments"
        )
        saveTheGoldenProject(app)

        try #require(app.project.text(at: archPath))
            .write(to: Self.goldens.appendingPathComponent("after.arch"), atomically: true, encoding: .utf8)
        try #require(app.project.text(at: controlsPath))
            .write(to: Self.goldens.appendingPathComponent("after.controls"), atomically: true, encoding: .utf8)
    }
}
