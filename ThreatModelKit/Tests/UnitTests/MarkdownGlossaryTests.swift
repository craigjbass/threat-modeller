import Testing
import ThreatModelKit
import TestSupport
import Foundation

struct MarkdownGlossaryTests {
    @Test func definesEveryWordTheReportUsesForItself() {
        let lines = MarkdownGlossary.lines()
        let text = lines.joined(separator: "\n")

        #expect(lines.first == "## Glossary")
        for word in [
            "Answered", "Implemented", "Not applicable", "Accepted",
            "Compensating control", "Pathway mitigation", "Mitigates edge",
            "Adopted", "Assumed", "Inherent score", "Residual score",
            "If the proposed are in place", "Risk tolerance", "Prior", "Raised by"
        ] {
            #expect(text.contains("| \(word) |"), "the glossary does not define \(word)")
        }
    }

    /// The glossary must define every word the report writes. This walks a
    /// report built from a model that exercises every section, reads every
    /// heading and every labelled term the render writes, and fails on the
    /// first one with no row in `MarkdownGlossary.entries`. A section a later
    /// change adds carries its own row, because the walk finds it too.
    @Test func theGlossaryDefinesEveryWordTheReportWrites() {
        let model = modelExercisingEverySection()
        let (history, change) = historyAndChange()
        let reports = BuildThreatModelReport(
            models: InMemoryThreatModelGateway(model),
            catalogue: CatalogueFixture.catalogue()
        )
        let report = reports.execute(
            BuildThreatModelReportRequest(history: history, change: change)
        ).report

        let pictureKey = MarkdownThreatPictures.key(
            threatId: "credential-theft",
            sourceId: "component:server"
        )
        let markdown = ExportModelAsMarkdown(reports: reports).execute(
            ExportModelAsMarkdownRequest(
                threatDiagrams: [pictureKey: "sequenceDiagram\n  Guard->>Server: blocks the theft\n"],
                history: history,
                change: change
            )
        ).markdown

        var dynamicNames = Set(report.components.map(\.name))
        dynamicNames.formUnion(report.zones.map(\.name))
        dynamicNames.formUnion(report.threats.map(\.name))
        dynamicNames.formUnion(report.threats.map(\.sourceName))
        dynamicNames.formUnion(report.attackTrees.map(\.name))
        dynamicNames.formUnion(report.protectionDependencies.map(\.protectorName))
        dynamicNames.formUnion(report.diagrams.map(\.label))
        dynamicNames.formUnion(report.thirdParties.map(\.name))
        dynamicNames.formUnion(report.threatActors.map(\.name))
        dynamicNames.formUnion(report.users.map(\.name))
        dynamicNames.insert(report.modelName)
        if let catalogueMoved = change.catalogueMoved { dynamicNames.insert(catalogueMoved) }

        let words = ReportVocabularyWalk.words(in: markdown, excluding: dynamicNames)
        let defined = Set(MarkdownGlossary.entries.map { $0.word.lowercased() })
        let missing = words.filter { defined.contains($0.lowercased()) == false }

        #expect(
            missing.isEmpty,
            "the glossary does not define: \(missing.sorted().joined(separator: ", "))"
        )
    }

    /// A model that turns on every section the report writes: a user and an
    /// adversary, a third party, a known vulnerability, a policy, an attack
    /// tree, an adopted and an assumed `mitigates` edge, a compensating
    /// control, a recommendation, an accepted risk, an assumption, a diagram
    /// and a faced threat actor.
    private func modelExercisingEverySection() -> ThreatModel {
        let workstationId = ComponentId("workstation")
        let guardId = ComponentId("guard")
        let serverId = ComponentId("server")
        let databaseId = ComponentId("database")
        let operatorId = ComponentId("operator")
        let userZone = ZoneId("user-zone")
        let rootZone = ZoneId("root-zone")

        let workstation = Component(
            id: workstationId,
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 0, y: 0),
            sensitivity: .internalData,
            customName: "Workstation",
            zoneId: userZone
        )
        let guardComponent = Component(
            id: guardId,
            technologyId: TechnologyId("aws-waf"),
            position: Point(x: 300, y: 0),
            sensitivity: .internalData,
            zoneId: rootZone
        )
        let server = Component(
            id: serverId,
            technologyId: TechnologyId("aws-ec2"),
            position: Point(x: 600, y: 0),
            sensitivity: .restricted,
            customName: "Secrets Server",
            holds: ["ssh-keys"],
            providedBy: "vendor-1",
            zoneId: rootZone,
            cves: ["CVE-2024-0001"]
        )
        let database = Component(
            id: databaseId,
            technologyId: TechnologyId("aws-rds"),
            position: Point(x: 900, y: 0),
            sensitivity: .restricted,
            customName: "Database",
            zoneId: rootZone
        )
        let operatorUser = Component(
            id: operatorId,
            technologyId: Component.userTechnologyId,
            position: Point(x: -300, y: 0),
            sensitivity: .internalData,
            customName: "Operator",
            user: UserFacts(
                role: "runs the deploy",
                uses: [UserUse(clientId: workstationId.value)],
                reaches: [workstationId.value],
                threatActorId: "insider",
                isAdversary: true
            )
        )

        let zones = [
            Zone(
                id: userZone,
                rect: Rect(x: -400, y: -100, width: 500, height: 300),
                name: "User zone",
                boundary: .privilege
            ),
            Zone(
                id: rootZone,
                rect: Rect(x: 200, y: -100, width: 900, height: 300),
                name: "Root zone",
                boundary: .privilege
            )
        ]

        let connections = [
            Connection(
                id: ConnectionId("workstation-server"),
                source: workstationId,
                target: serverId,
                kind: .ipc,
                description: "Reads the secret"
            ),
            Connection(
                id: ConnectionId("server-database"),
                source: serverId,
                target: databaseId,
                kind: .network,
                description: "Reads records"
            )
        ]

        let mitigatesEdges = [
            MitigatesEdge(
                source: guardId,
                target: serverId,
                threatIds: [ThreatId("credential-theft")],
            ),
            MitigatesEdge(
                source: guardId,
                target: databaseId,
                threatIds: [ThreatId("misconfiguration")],
                status: .proposed,
                action: EdgeAction(
                    label: "adopt-waf-on-database",
                    text: "Adopt the WAF rule on the database."
                )
            )
        ]

        let acceptedControlKey = ControlIdentity.componentControl(
            componentId: serverId,
            threatId: ThreatId("credential-theft"),
            description: "Enforce IMDSv2 to block SSRF-based credential theft",
            isTechnologySpecific: true
        )

        return ThreatModel(
            name: "Vocabulary Walk",
            components: [workstation, guardComponent, server, database, operatorUser],
            connections: connections,
            zones: zones,
            controlStatuses: [acceptedControlKey: .accepted],
            compensatingControls: [
                ThreatKey(threatId: "dos-attack", sourceId: "component:\(serverId.value)"): [
                    CompensatingControl(
                        label: "Rate limiter",
                        reducesRiskBy: 10,
                        rationale: "A rate limiter throttles the flood.",
                        proof: ControlProof(
                            evidence: .tested,
                            reference: "test-a",
                            verifiedOn: GovernanceDate(year: 2026, month: 1, day: 5)
                        )
                    )
                ]
            ],
            mitigatesEdges: mitigatesEdges,
            recommendations: [
                ThreatKey(threatId: "misconfiguration", sourceId: "component:\(databaseId.value)"): [
                    Recommendation(text: "Rotate the database credential on a schedule.")
                ]
            ],
            useCases: [SystemUseCase(label: "deploy", text: "The operator deploys a new release.")],
            exclusions: [
                SystemExclusion(
                    label: "payments",
                    text: "Payment processing.",
                    rationale: "A separate system handles it."
                )
            ],
            systemAssets: [
                SystemAsset(
                    id: "ssh-keys",
                    name: "SSH keys",
                    classification: .restricted,
                    description: "The root SSH private key.",
                    owner: "Platform"
                )
            ],
            thirdParties: [
                ThirdParty(
                    id: "vendor-1",
                    name: "Vendor One",
                    description: "Managed hosting for the secrets server.",
                    kind: .infrastructure,
                    payingCustomer: true,
                    uptime: .hard,
                    uptimeNotes: "No support on weekends.",
                    owner: "Procurement"
                )
            ],
            diagrams: [
                SystemDiagram(
                    label: "Login sequence",
                    kind: "mermaid",
                    text: "sequenceDiagram\n  Operator->>Server: login\n"
                )
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
                        threatId: "misconfiguration", sourceKind: "component", sourceId: databaseId.value
                    ),
                    root: .step(SourceTreeStep(
                        target: SourceTreeTarget(
                            threatId: "credential-theft", sourceKind: "component", sourceId: serverId.value
                        )
                    ))
                )
            ],
            riskTolerance: .low,
            owner: "Security Team",
            documentFacts: DocumentFacts(
                description: "A model built to exercise every report section.",
                authors: ["Craig Bass"],
                links: ["https://example.com/model"],
                repositories: ["github.com/example/repo"],
                created: "2026-01-01",
                reviewed: "2026-01-15",
                version: "1.0",
                attributes: [(name: "Data residency", value: "EU")]
            ),
            policy: PolicySource(maxOpenAtLevel: .low),
            acceptedRisks: [
                ThreatKey(threatId: "credential-theft", sourceId: "component:\(serverId.value)"): [
                    RiskAcceptance(
                        control: "Enforce IMDSv2 to block SSRF-based credential theft",
                        owner: "Head of Platform",
                        acceptedOn: GovernanceDate(year: 2020, month: 1, day: 1),
                        reviewBy: GovernanceDate(year: 2020, month: 6, day: 1),
                        rationale: "The team accepted this for a quarter.",
                        sources: []
                    )
                ]
            ],
            facedActorIds: ["insider"],
            localActors: [
                ThreatActor(
                    id: ThreatActorId("insider"),
                    name: "Insider",
                    description: "An operator who misuses access.",
                    capability: .targeted,
                    intent: "misuse access",
                    performs: [ThreatId("credential-theft")]
                )
            ],
            vulnerabilities: [
                "CVE-2024-0001": KnownVulnerability(
                    id: "CVE-2024-0001",
                    cvss: 9.8,
                    cvssVersion: "3.1",
                    epss: 0.5,
                    isKnownExploited: true,
                    kevDateAdded: "2024-01-01",
                    modified: "2024-02-01",
                    summary: "Remote code execution."
                )
            ]
        )
    }

    /// Two sampled commits and what moved between them, so the report writes
    /// its Risk over time and What changed sections too.
    private func historyAndChange() -> (history: [RiskHistoryRow], change: RiskChange) {
        let now = SourceCommit(
            hash: "1111111111111111111111111111111111aaaa",
            author: "Craig Bass",
            date: Date(timeIntervalSince1970: 1_700_000_000),
            subject: "Add the secrets server"
        )
        let then = SourceCommit(
            hash: "2222222222222222222222222222222222bbbb",
            author: "Craig Bass",
            date: Date(timeIntervalSince1970: 1_690_000_000),
            subject: "Initial model"
        )
        let history = [
            RiskHistoryRow(
                commit: now,
                numbers: RiskHistoryNumbers(
                    totalScore: 120, byLevel: ["Critical": 1], worstScore: 40,
                    threatCount: 10, acceptedRisks: 1, openAttackTrees: 1, catalogueTag: "v2"
                )
            ),
            RiskHistoryRow(
                commit: then,
                numbers: RiskHistoryNumbers(
                    totalScore: 90, byLevel: ["High": 1], worstScore: 30,
                    threatCount: 8, acceptedRisks: 0, openAttackTrees: 0, catalogueTag: "v1"
                )
            )
        ]
        let change = RiskChange(
            raised: ["credential-theft on Secrets Server"],
            gone: ["dos-attack on Secrets Server"],
            controlsChanged: ["Enforce IMDSv2 to block SSRF-based credential theft now implemented"],
            acceptedAdded: ["credential-theft on Secrets Server accepted"],
            reviewDatesMoved: ["credential-theft on Secrets Server review moved to 2026-06-01"],
            scoreDeltas: [ElementDelta(name: "Secrets Server", now: 40, then: 30)],
            catalogueMoved: "v1 to v2",
            totalNow: 120,
            totalThen: 90
        )
        return (history, change)
    }
}

/// Reads the words a rendered report introduces: its headings and its
/// labelled bold terms. A word built only from data the fixture itself
/// supplies (a component's name, a zone's name, a threat's name, and so on)
/// is not a word the reader needs the glossary for, so the walk drops it.
private enum ReportVocabularyWalk {
    static func words(in markdown: String, excluding dynamicNames: Set<String>) -> Set<String> {
        var words: Set<String> = []
        for line in markdown.split(separator: "\n", omittingEmptySubsequences: false) {
            let text = String(line)
            if let heading = heading(in: text), contains(heading, anyOf: dynamicNames) == false {
                words.insert(word(from: heading))
            }
            for term in boldTerms(in: text) where contains(term, anyOf: dynamicNames) == false {
                words.insert(term)
            }
        }
        return words
    }

    private static let headingPrefixes = ["### ", "## ", "# "]

    private static func heading(in line: String) -> String? {
        for prefix in headingPrefixes where line.hasPrefix(prefix) {
            return String(line.dropFirst(prefix.count))
        }
        return nil
    }

    /// The part of a heading before its dynamic suffix, when it states one:
    /// `"Appendix A \u{2014} Full threat register"` reads as `"Appendix A"`.
    private static func word(from heading: String) -> String {
        guard let range = heading.range(of: " \u{2014} ") else { return heading }
        return String(heading[..<range.lowerBound])
    }

    private static func boldTerms(in line: String) -> [String] {
        var terms: [String] = []
        var remainder = Substring(line)
        while let openRange = remainder.range(of: "**") {
            let afterOpen = remainder[openRange.upperBound...]
            guard let closeRange = afterOpen.range(of: "**") else { break }
            var term = String(afterOpen[afterOpen.startIndex..<closeRange.lowerBound])
            if term.hasSuffix(".") { term = String(term.dropLast()) }
            if term.isEmpty == false { terms.append(term) }
            remainder = afterOpen[closeRange.upperBound...]
        }
        return terms
    }

    private static func contains(_ text: String, anyOf names: Set<String>) -> Bool {
        names.contains { name in name.isEmpty == false && text.contains(name) }
    }
}
