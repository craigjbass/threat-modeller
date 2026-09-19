import Foundation
import Testing
import ThreatModelKit
import TestSupport

/// `docs/OTM-MAPPING.md` states what the OTM, the threatcl and the JSON
/// exports each carry and each drop. This drives all three exporters on one
/// model that carries a recommendation, an accepted risk, an assumption, a
/// use case, a user, a third party, a known vulnerability, a policy, a
/// threat actor, an attack tree, a compensating control, a mermaid and a d2
/// diagram, and a threat with a likelihood rationale, then reads each
/// export's bytes to prove the document's carries and drops are both true.
struct OtmMappingDocumentationTests {
    private let catalogue = CatalogueFixture.catalogue()

    private func model() -> ThreatModel {
        let zoneId = ZoneId("z1")
        let serverId = ComponentId("server")
        let guardId = ComponentId("guard")
        let operatorId = ComponentId("operator")

        let server = Component(
            id: serverId,
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .restricted,
            holds: ["ssh-keys"],
            providedBy: "vendor-1",
            zoneId: zoneId,
            tags: ["pci"],
            version: "2.0.1",
            cves: ["CVE-2024-0002"]
        )
        let guardComponent = Component(
            id: guardId,
            technologyId: TechnologyId("aws-waf"),
            position: Point(x: 300, y: 0),
            sensitivity: .internalData
        )
        let operatorUser = Component(
            id: operatorId,
            technologyId: Component.userTechnologyId,
            position: Point(x: -300, y: 0),
            sensitivity: .internalData,
            customName: "Operator",
            user: UserFacts(
                role: "runs the deploy",
                threatActorId: "insider",
                isAdversary: true
            )
        )

        return ThreatModel(
            name: "Payments",
            components: [server, guardComponent, operatorUser],
            zones: [
                Zone(
                    id: zoneId,
                    rect: Rect(x: -50, y: -50, width: 400, height: 300),
                    boundary: .privilege
                )
            ],
            controlStatuses: [
                ControlIdentity.componentControl(
                    componentId: serverId,
                    threatId: ThreatId("misconfiguration"),
                    description: "Scan configuration continuously",
                    isTechnologySpecific: false
                ): .accepted
            ],
            compensatingControls: [
                ThreatKey(threatId: "dos-attack", sourceId: "component:\(serverId.value)"): [
                    CompensatingControl(
                        label: "Rate limiter",
                        reducesRiskBy: 10,
                        rationale: "A rate limiter throttles the flood."
                    )
                ]
            ],
            mitigatesEdges: [
                MitigatesEdge(
                    source: guardId,
                    target: serverId,
                    threatIds: [ThreatId("misconfiguration")],
                    reducesRiskBy: 50
                )
            ],
            recommendations: [
                ThreatKey(threatId: "credential-theft", sourceId: "component:\(serverId.value)"): [
                    Recommendation(text: "Rotate the credential every quarter.")
                ]
            ],
            likelihoodFindings: [
                ThreatKey(threatId: "credential-theft", sourceId: "component:\(serverId.value)"): LikelihoodFinding(
                    label: "no campaign has used this",
                    likelihood: .research,
                    rationale: "No public reporting names this technique against this platform."
                )
            ],
            useCases: [SystemUseCase(label: "deploy", text: "The operator deploys a new release.")],
            systemAssets: [SystemAsset(id: "ssh-keys", name: "SSH keys", classification: .restricted)],
            thirdParties: [
                ThirdParty(id: "vendor-1", name: "Vendor One", description: "Managed hosting.")
            ],
            diagrams: [
                SystemDiagram(label: "Login flow", kind: "mermaid", text: "sequenceDiagram\n  A->>B: login\n"),
                SystemDiagram(label: "Network topology", kind: "d2", text: "shape: rectangle\n")
            ],
            assumptions: [
                SystemAssumption(label: "no-mfa-bypass", text: "Nobody bypasses MFA.", owner: "Security")
            ],
            attackTrees: [
                SourceAttackTree(
                    id: "read-every-record",
                    name: "Read every record",
                    raisesRiskBy: 40,
                    goal: SourceTreeTarget(
                        threatId: "misconfiguration", sourceKind: "component", sourceId: serverId.value
                    ),
                    root: .step(SourceTreeStep(
                        target: SourceTreeTarget(
                            threatId: "credential-theft", sourceKind: "component", sourceId: serverId.value
                        )
                    ))
                )
            ],
            owner: "Security Team",
            documentFacts: DocumentFacts(description: "A model built to prove the export mapping."),
            policy: PolicySource(maxOpenAtLevel: .low),
            acceptedRisks: [
                ThreatKey(threatId: "misconfiguration", sourceId: "component:\(serverId.value)"): [
                    RiskAcceptance(
                        control: "Scan configuration continuously",
                        owner: "Head of Platform",
                        rationale: "The team accepted this for a quarter."
                    )
                ]
            ],
            facedActorIds: ["insider"],
            localActors: [
                ThreatActor(id: ThreatActorId("insider"), name: "Insider", capability: .targeted)
            ],
            vulnerabilities: [
                "CVE-2024-0002": KnownVulnerability(
                    id: "CVE-2024-0002",
                    cvss: 7.1,
                    summary: "Unauthenticated remote code execution in the login handler."
                )
            ]
        )
    }

    private var reports: BuildThreatModelReportUseCase {
        BuildThreatModelReport(models: InMemoryThreatModelGateway(model()), catalogue: catalogue)
    }

    // MARK: --format otm

    @Test func theOtmFileCarriesWhatTheDocumentClaims() throws {
        let response = ExportModelAsOtm(reports: reports).execute(ExportModelAsOtmRequest())
        let json = try #require(
            try JSONSerialization.jsonObject(with: Data(response.json.utf8)) as? [String: Any]
        )

        let project = try #require(json["project"] as? [String: Any])
        #expect(project["name"] as? String == "Payments")
        #expect(project["owner"] as? String == "Security Team")
        #expect(project["description"] as? String == "A model built to prove the export mapping.")

        let representations = try #require(json["representations"] as? [[String: Any]])
        #expect(representations.count == 1)

        let report = reports.execute(BuildThreatModelReportRequest()).report
        let controlsOnly = report.threats.reduce(0) { $0 + $1.controls.count }
        let mitigations = try #require(json["mitigations"] as? [[String: Any]])
        #expect(mitigations.count == controlsOnly)
    }

    @Test func theOtmFileDropsWhatTheDocumentClaims() throws {
        let response = ExportModelAsOtm(reports: reports).execute(ExportModelAsOtmRequest())
        let text = response.json

        for dropped in [
            "Rotate the credential every quarter.",
            "Head of Platform",
            "Nobody bypasses MFA.",
            "runs the deploy",
            "Vendor One",
            "Unauthenticated remote code execution",
            "Read every record",
            "sequenceDiagram",
            "shape: rectangle",
            "Rate limiter",
            "Privilege Boundary",
            "2.0.1"
        ] {
            #expect(text.contains(dropped) == false, "the OTM file states \"\(dropped)\", which the document says it drops")
        }
    }

    // MARK: --format threatcl

    @Test func theThreatclFileCarriesWhatTheDocumentClaims() throws {
        let hcl = ExportModelAsThreatcl(reports: reports).execute(ExportModelAsThreatclRequest()).hcl

        #expect(hcl.contains("information_asset \"SSH keys\""))
        #expect(hcl.contains("The operator deploys a new release."))
        #expect(hcl.contains("Assumed: no-mfa-bypass: Nobody bypasses MFA."))
        #expect(hcl.contains("third_party_dependency \"Vendor One\""))
        #expect(hcl.contains("sequenceDiagram"))
        #expect(hcl.contains("Rate limiter"))
        #expect(hcl.contains("No public reporting names this technique against this platform."))
    }

    @Test func theThreatclFileDropsWhatTheDocumentClaims() throws {
        let hcl = ExportModelAsThreatcl(reports: reports).execute(ExportModelAsThreatclRequest()).hcl

        for dropped in [
            "Head of Platform",
            "Read every record",
            "Insider",
            "shape: rectangle",
            "runs the deploy",
            "2.0.1",
            "\"pci\""
        ] {
            #expect(hcl.contains(dropped) == false, "the threatcl file states \"\(dropped)\", which the document says it drops")
        }

    }

    @Test func theThreatclRationaleStatesBothScoresBesideTheLikelihoodRationale() throws {
        let hcl = ExportModelAsThreatcl(reports: reports).execute(ExportModelAsThreatclRequest()).hcl

        let stanzaStart = try #require(hcl.range(of: "threat \"Credential Theft on EC2\" {"))
        let stanzaEnd = try #require(
            hcl.range(of: "\n  threat \"", range: stanzaStart.upperBound..<hcl.endIndex)
        )
        let stanza = hcl[stanzaStart.lowerBound..<stanzaEnd.lowerBound]
        #expect(stanza.contains("No public reporting names this technique against this platform."))
        #expect(stanza.contains("before controls, on EC2."))
    }

    @Test func theThreatclExportNamesTheDiagramItDropped() {
        let response = ExportModelAsThreatcl(reports: reports)
            .execute(ExportModelAsThreatclRequest())

        #expect(
            response.diagnostics.contains {
                $0.contains("Network topology") && $0.contains("d2")
            },
            "the export records no diagnostic for the dropped diagram: \(response.diagnostics)"
        )
    }

    // MARK: --format json

    @Test func theJsonFileCarriesWhatTheDocumentClaims() throws {
        let response = ExportModelAsJson(reports: reports).execute(ExportModelAsJsonRequest())
        let json = try #require(
            try JSONSerialization.jsonObject(with: Data(response.json.utf8)) as? [String: Any]
        )

        let recommendations = try #require(json["recommendations"] as? [[String: Any]])
        #expect(recommendations.first?["text"] as? String == "Rotate the credential every quarter.")

        let acceptedRisks = try #require(json["acceptedRisks"] as? [[String: Any]])
        #expect(acceptedRisks.first?["owner"] as? String == "Head of Platform")

        let assumptions = try #require(json["assumptions"] as? [[String: Any]])
        #expect(assumptions.first?["text"] as? String == "Nobody bypasses MFA.")

        let thirdParties = try #require(json["thirdParties"] as? [[String: Any]])
        #expect(thirdParties.first?["name"] as? String == "Vendor One")

        let knownVulnerabilities = try #require(json["knownVulnerabilities"] as? [[String: Any]])
        #expect(knownVulnerabilities.first?["cveId"] as? String == "CVE-2024-0002")

        let zones = try #require(json["zones"] as? [[String: Any]])
        #expect(zones.first?["boundary"] as? String == "Privilege Boundary")
    }

    @Test func theJsonFileCarriesThePeopleTheTreesAndTheDiagrams() throws {
        let response = ExportModelAsJson(reports: reports).execute(ExportModelAsJsonRequest())
        let json = try #require(
            try JSONSerialization.jsonObject(with: Data(response.json.utf8)) as? [String: Any]
        )

        let users = try #require(json["users"] as? [[String: Any]])
        let operatorUser = try #require(users.first { $0["name"] as? String == "Operator" })
        #expect(operatorUser["role"] as? String == "runs the deploy")
        #expect(operatorUser["isAdversary"] as? Bool == true)

        let actors = try #require(json["threatActors"] as? [[String: Any]])
        #expect(actors.contains { $0["name"] as? String == "Insider" })

        let attackTrees = try #require(json["attackTrees"] as? [[String: Any]])
        #expect(attackTrees.contains { $0["name"] as? String == "Read every record" })

        let diagrams = try #require(json["diagrams"] as? [[String: Any]])
        #expect(diagrams.contains { ($0["text"] as? String)?.contains("sequenceDiagram") == true })
        #expect(diagrams.contains { ($0["text"] as? String)?.contains("shape: rectangle") == true })
    }

    @Test func theJsonFileDropsWhatTheDocumentClaims() throws {
        let response = ExportModelAsJson(reports: reports).execute(ExportModelAsJsonRequest())
        let json = try #require(
            try JSONSerialization.jsonObject(with: Data(response.json.utf8)) as? [String: Any]
        )

        for dropped in ["policy", "attackPaths", "protectionDependencies", "history", "rollups"] {
            #expect(json[dropped] == nil, "the JSON file states \(dropped), which the document says it drops")
        }
    }
}
