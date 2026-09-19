public protocol BuildThreatModelReportUseCase {
    func execute(_ request: BuildThreatModelReportRequest) -> BuildThreatModelReportResponse
}

public struct BuildThreatModelReportRequest: Equatable, Sendable {
    /// What the model scored at each sampled commit, newest first. Empty when
    /// nobody asked for the history: it is read at a person's request and
    /// never at open time.
    public let history: [RiskHistoryRow]
    /// True when the bound left commits out.
    public let historyTruncated: Bool
    /// What changed between the previous sampled commit and the working tree.
    public let change: RiskChange?

    public init(
        history: [RiskHistoryRow] = [],
        historyTruncated: Bool = false,
        change: RiskChange? = nil
    ) {
        self.history = history
        self.historyTruncated = historyTruncated
        self.change = change
    }
}

public struct BuildThreatModelReportResponse: Equatable, Sendable {
    public let report: Report

    public init(report: Report) {
        self.report = report
    }
}

/// Turns the model and its assessment into the one tree every report reads.
///
/// It reads the same resolution the sidebar reads, so a report can never
/// disagree with what the user saw on screen.
public struct BuildThreatModelReport: BuildThreatModelReportUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    /// The day a review date is measured against. No report reads the wall
    /// clock on its own.
    private let clock: Clock
    /// The ATT&CK data on this machine, so a technique line reads a name
    /// beside its id. Nil, or a machine that has not synchronised, prints
    /// bare ids.
    private let mitre: MitreActorSource?

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        clock: Clock = SystemClock(),
        mitre: MitreActorSource? = nil
    ) {
        self.models = models
        self.catalogue = catalogue
        self.clock = clock
        self.mitre = mitre
    }

    public func execute(_ request: BuildThreatModelReportRequest) -> BuildThreatModelReportResponse {
        let model = models.current()
        let taxonomy = catalogue.taxonomy()
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        let assessment = AssessThreatModel(models: models, catalogue: catalogue)
            .execute(AssessThreatModelRequest())

        // What each technique is called, read once. A machine that has not
        // synchronised holds none and the report prints bare ids.
        var techniqueNames: [String: String] = [:]
        if let mitre {
            for id in Set(assessment.threats.flatMap { $0.mitreTechniques.map(\.id) }) {
                guard let technique = mitre.technique(id) else { continue }
                techniqueNames[id] = technique.tactics.first.map {
                    "\(technique.name) (\($0))"
                } ?? technique.name
            }
        }
        let summary = SummariseRisk(models: models, catalogue: catalogue)
            .execute(SummariseRiskRequest())
        let leverage = AssessLeverage(models: models, catalogue: catalogue)
            .execute(AssessLeverageRequest())

        var nameById: [ComponentId: String] = [:]
        for component in model.components {
            nameById[component.id] = component.customName
                ?? (component.isUser ? nil : lookup.findById(component.technologyId)?.name)
                ?? (component.isUser ? component.id.value : component.technologyId.value)
        }
        let nameOf: (ComponentId) -> String = { nameById[$0] ?? $0.value }

        let zonesById = Dictionary(
            model.zones.map { ($0.id, $0) },
            uniquingKeysWith: { _, later in later }
        )
        let zoneByComponent = Dictionary(
            uniqueKeysWithValues: model.components.map { component in
                (component.id, component.zoneId.flatMap { zonesById[$0] })
            }
        )

        // What each element holds or carries, by the source id the resolver
        // mints, so a threat can name the assets at risk on its own source.
        var assetNamesBySource: [String: [String]] = [:]
        let assetNameById = Dictionary(
            model.systemAssets.map { ($0.id, $0.name) },
            uniquingKeysWith: { first, _ in first }
        )
        for component in model.components where component.holds.isEmpty == false {
            assetNamesBySource["component:\(component.id.value)"] =
                component.holds.compactMap { assetNameById[$0] }
        }
        for connection in model.connections where connection.carries.isEmpty == false {
            assetNamesBySource["connection:\(connection.id.value)"] =
                connection.carries.compactMap { assetNameById[$0] }
        }

        // An open tree raises its goal, so the goal's stanza names the tree
        // and the score the stage received. A stale tree and a closed tree
        // raise nothing and name nothing.
        var treeByGoal: [ThreatKey: BoundAttackTree] = [:]
        for tree in assessment.attackTrees where tree.isStale == false && tree.isOpen {
            let strongest = treeByGoal[tree.goal]
            if strongest == nil || tree.score > (strongest?.score ?? 0) {
                treeByGoal[tree.goal] = tree
            }
        }

        let threats = assessment.threats.map { assessed in
            Self.threat(
                from: assessed,
                tree: treeByGoal[
                    ThreatKey(threatId: assessed.threatId, sourceId: assessed.source.id)
                ],
                compensating: assessed.compensating.map {
                    ReportCompensatingControl(
                        label: $0.label,
                        reducesRiskBy: $0.reducesRiskBy,
                        rationale: $0.rationale,
                        sources: $0.sources,
                        evidence: $0.evidence
                    )
                },
                // The assessment names STRIDE by id. A report is read
                // by people, so it names it by label.
                strideLabels: assessed.stride.compactMap {
                    taxonomy.strideCategory(id: StrideId($0))?.label
                },
                impactLabels: assessed.impacts.compactMap {
                    ThreatImpact(rawValue: $0)?.label
                },
                assetsAtRisk: assetNamesBySource[assessed.source.id] ?? [],
                overrides: catalogue.overrides(),
                techniqueNames: techniqueNames
            )
        }

        let tolerance = model.effectiveRiskTolerance

        let zones = model.zones.map { zone in
            let held = model.components.filter { zoneByComponent[$0.id] ?? nil == zone }
            return ReportZone(
                name: zone.displayName,
                networkZoneLabel: zone.networkZone.label,
                networkTypeLabel: zone.networkType.label,
                componentNames: held.compactMap { nameById[$0.id] },
                componentIds: held.map(\.id.value),
                riskReductionPercent: zone.networkZone == .privateZone && zone.riskReductionEnabled
                    ? zone.riskReductionPercent
                    : nil,
                boundaryLabel: zone.boundary.label
            )
        }

        let attack = AttackPaths.build(
            components: model.components,
            connections: model.connections,
            zones: model.zones,
            threats: threats,
            nameOf: nameOf
        )

        // An edge names no assumption, so the assumed `mitigates` edges
        // travel as their own list rather than repeated under every
        // assumption.
        let assumedMitigations = model.mitigatesEdges
            .filter { $0.effectiveStatus == .assumed }
            .map {
                ReportAssumedMitigation(
                    protectorName: nameOf($0.source),
                    protectedName: nameOf($0.target),
                    threatIds: $0.threatIds.map(\.value),
                    reducesRiskBy: $0.reducesRiskBy
                )
            }
        let assumptions = model.assumptions.map { assumption in
            ReportAssumption(
                label: assumption.label,
                text: assumption.text,
                owner: assumption.owner
            )
        }

        // One row per named asset. The worst open threat is the worst on
        // anything that holds it or carries it, because a reader asks what
        // stands against this asset, not against one element.
        let dataInventory = model.systemAssets.map { asset -> ReportAssetRow in
            let holders = model.components.filter { $0.holds.contains(asset.id) }
            let carriers = model.connections.filter { $0.carries.contains(asset.id) }
            var sourceIds = Set(holders.map { "component:\($0.id.value)" })
            sourceIds.formUnion(carriers.map { "connection:\($0.id.value)" })
            let worst = threats
                .filter { sourceIds.contains($0.sourceId) && $0.isOpen }
                .sorted(by: ReportThreat.worstFirst)
                .first
            return ReportAssetRow(
                id: asset.id,
                name: asset.name,
                classificationLabel: asset.classification.label(in: catalogue.classifications()),
                owner: asset.owner,
                description: asset.description,
                heldBy: holders.map { nameById[$0.id] ?? $0.id.value },
                carriedBy: carriers.map {
                    "\(nameById[$0.source] ?? $0.source.value) \u{2192} "
                        + "\(nameById[$0.target] ?? $0.target.value)"
                },
                worstOpenThreat: worst?.name,
                worstOpenScore: worst?.riskScore
            )
        }

        // One row per CVE per component, ranked against the lock file with
        // the policy's thresholds. A CVE two components state writes two rows.
        let thresholds = VulnerabilityPriority.Thresholds(policy: model.policy)
        var knownVulnerabilities: [ReportKnownVulnerability] = []
        for component in model.components where component.cves.isEmpty == false {
            for ranked in AssessedVulnerability.of(
                cves: component.cves,
                held: model.vulnerabilities,
                thresholds: thresholds
            ) {
                knownVulnerabilities.append(
                    ReportKnownVulnerability(
                        cveId: ranked.cveId,
                        componentName: nameById[component.id] ?? component.id.value,
                        version: component.version,
                        cvss: ranked.cvss,
                        epss: ranked.epss,
                        isKnownExploited: ranked.isKnownExploited,
                        priorityLabel: ranked.priorityLabel
                    )
                )
            }
        }
        knownVulnerabilities = MarkdownKnownVulnerabilities.ordered(knownVulnerabilities)

        let thirdParties = model.thirdParties.map { party -> ReportThirdParty in
            let provided = model.components.filter { $0.providedBy == party.id }
            var names: [String] = []
            for component in provided {
                for held in component.holds {
                    guard let name = assetNameById[held], names.contains(name) == false else {
                        continue
                    }
                    names.append(name)
                }
            }
            return ReportThirdParty(
                id: party.id,
                name: party.name,
                description: party.description,
                kindLabel: party.kind.label,
                payingCustomer: party.payingCustomer,
                uptimeLabel: party.uptime.label,
                uptimeNotes: party.uptimeNotes,
                owner: party.owner,
                link: party.link,
                provides: provided.map { nameById[$0.id] ?? $0.id.value },
                assetNames: names
            )
        }

        let useCases = model.useCases.map {
            ReportUseCase(label: $0.label, text: $0.text)
        }
        let exclusions = model.exclusions.map {
            ReportExclusion(label: $0.label, text: $0.text, rationale: $0.rationale)
        }

        let recommendations = RecommendationsReport.build(
            threats: threats,
            recommendations: model.recommendations,
            governance: model.plannedWork,
            routeClosingThreats: Set(RouteClosing.openSteps(on: assessment.attackTrees).keys)
        )

        // A row for every accepted control, governed or not, so a reader sees
        // the ungoverned ones as a row of dashes rather than not at all.
        let today = CheckGovernance.today(clock.now())
        var acceptedRisks: [ReportAcceptedRisk] = []
        for threat in threats {
            let key = ThreatKey(threatId: threat.threatId, sourceId: threat.sourceId)
            for control in threat.controls where control.statusLabel == ControlStatus.accepted.label {
                let governed = model.acceptedRisks[key]?.first { $0.control == control.description }
                acceptedRisks.append(
                    ReportAcceptedRisk(
                        threatName: threat.name,
                        sourceName: threat.sourceName,
                        riskScore: threat.riskScore,
                        control: control.description,
                        owner: governed?.owner ?? "",
                        acceptedOn: governed?.acceptedOn?.description,
                        reviewBy: governed?.reviewBy?.description,
                        rationale: governed?.rationale ?? "",
                        isOverdue: governed?.isOverdue(on: today) ?? false
                    )
                )
            }
        }
        acceptedRisks.sort { left, right in
            if left.riskScore != right.riskScore { return left.riskScore > right.riskScore }
            if left.threatName != right.threatName { return left.threatName < right.threatName }
            return left.control < right.control
        }

        let findingsCut = ReportFindingsCut.build(from: threats, tolerance: tolerance)

        let actions = leverage.leverage.map {
            ReportAction(
                label: $0.action.label,
                text: $0.action.text,
                note: $0.action.note,
                blockedBy: $0.action.blockedBy,
                sources: $0.action.sources,
                governance: model.actionWork[$0.action.label]?.says,
                removes: $0.removes,
                totalResidual: $0.totalResidual,
                threatsMoved: $0.threatsMoved,
                worstBefore: $0.worstBefore,
                worstAfter: $0.worstAfter
            )
        }

        // The rules the project states for itself, read over this model, by
        // the same bodies the check runs.
        let policyRules = model.policy.map { policy in
            PolicyRules.evaluate(
                policy,
                reading: PolicyRules.Reading(
                    threats: threats.map { threat in
                        PolicyRules.Threat(
                            key: ThreatKey(threatId: threat.threatId, sourceId: threat.sourceId),
                            threatId: threat.threatId,
                            sourceKind: threat.sourceKind.lowercased(),
                            sourceId: threat.sourceId,
                            riskLevel: RiskLevel(rawValue: threat.riskLevel) ?? .low,
                            levelBeforeControls: RiskScore(value: threat.inherentScore).level,
                            isAnswered: threat.controls.contains(where: { $0.isImplemented })
                                || threat.compensating.isEmpty == false,
                            unevidencedControls: threat.controls
                                .filter { $0.isImplemented && $0.evidence == "no evidence" }
                                .map(\.description),
                            acceptedControls: threat.controls
                                .filter { $0.statusLabel == ControlStatus.accepted.label }
                                .map(\.description)
                        )
                    },
                    elements: model.components.map { component in
                        PolicyRules.Element(
                            id: component.id.value,
                            sensitivity: component.sensitivity,
                            zone: (zoneByComponent[component.id] ?? nil)?.networkZone
                        )
                    },
                    acceptedRisks: model.acceptedRisks,
                    assumptions: model.assumptions.map { ($0.label, $0.owner ?? "") },
                    systemOwner: model.owner
                )
            )
        } ?? []

        // What the report says about the document itself.
        let control = DocumentControl(
            systemName: model.name,
            description: model.documentFacts.description.isEmpty
                ? nil
                : model.documentFacts.description,
            owner: model.owner.isEmpty ? nil : model.owner,
            authors: model.documentFacts.authors,
            version: model.documentFacts.version.isEmpty ? nil : model.documentFacts.version,
            created: model.documentFacts.created.isEmpty ? nil : model.documentFacts.created,
            reviewed: model.documentFacts.reviewed.isEmpty ? nil : model.documentFacts.reviewed,
            catalogueTag: model.catalogueVersion?.tag ?? catalogue.version().tag,
            links: model.documentFacts.links,
            repositories: model.documentFacts.repositories,
            attributes: model.documentFacts.attributes
        )

        return BuildThreatModelReportResponse(
            report: Report(
                modelName: model.name,
                documentControl: control,
                catalogueTag: model.catalogueVersion?.tag ?? catalogue.version().tag,
                summary: ReportSummary(
                    totalThreats: summary.totalThreats,
                    byLevel: summary.byLevel.map { ReportCount(label: $0.label, count: $0.count) },
                    byStride: summary.byStride.map { ReportCount(label: $0.label, count: $0.count) },
                    controlsOffered: summary.controlsOffered,
                    controlsRecorded: summary.controlsRecorded,
                    byControlStatus: Self.byStatus(assessment.threats)
                ),
                // A user is not a component: the Scope section lists it.
                components: model.components.filter { $0.isUser == false }.map { component in
                    ReportComponent(
                        id: component.id.value,
                        name: nameById[component.id] ?? component.technologyId.value,
                        technologyId: component.technologyId.value,
                        categoryId: lookup.findById(component.technologyId)?.category.value ?? "",
                        sensitivityLabel: component.effectiveSensitivity.label(in: catalogue.classifications()),
                        zoneName: zoneByComponent[component.id]??.displayName,
                        assetNames: component.assets.map(\.name),
                        privilegeLabel: component.runsAs.label,
                        shapeId: component.resolvedShape(
                            providerId: lookup.findById(component.technologyId)?.provider.value ?? "",
                            categoryId: lookup.findById(component.technologyId)?.category.value ?? ""
                        ).rawValue,
                        statusLabel: component.status.label
                    )
                },
                connections: model.connections.map { connection in
                    ReportConnection(
                        sourceName: nameById[connection.source] ?? connection.source.value,
                        targetName: nameById[connection.target] ?? connection.target.value,
                        kindLabel: connection.kind.label,
                        description: connection.description
                    )
                },
                zones: zones,
                threats: threats,
                recommendations: recommendations,
                protectionDependencies: ProtectionDependenciesReport.build(
                    assessment.protectionDependencies,
                    threats: threats,
                    zones: zones,
                    nameOfComponent: { nameOf(ComponentId($0)) }
                ),
                attackPaths: attack.paths,
                attackPathsNotListed: attack.notListed,
                attackPathPrefix: attack.prefix,
                attackPathsBeyondAppendix: attack.beyond,
                rollups: ReportRollups.build(threats: threats, zones: zones),
                assumptions: assumptions,
                useCases: useCases,
                users: Self.users(
                    of: model,
                    nameOf: nameOf,
                    actors: ThreatActorLookup(model: model, catalogue: catalogue)
                ),
                dataInventory: dataInventory,
                thirdParties: thirdParties,
                knownVulnerabilities: knownVulnerabilities,
                vulnerabilityThresholds: thresholds,
                diagrams: model.diagrams.map {
                    ReportDiagram(label: $0.label, kind: $0.kind, text: $0.text)
                },
                exclusions: exclusions,
                assumedMitigations: assumedMitigations,
                findings: findingsCut,
                toleranceLabel: tolerance.label,
                executiveSummary: ReportExecutiveSummary.build(
                    threats: threats,
                    recommendations: recommendations,
                    tolerance: tolerance,
                    findings: findingsCut,
                    actions: actions,
                    acceptedRisks: acceptedRisks,
                    documentControl: control,
                    today: CheckGovernance.today(clock.now()),
                    exclusionCount: exclusions.count,
                    hardDependencyCount: model.thirdParties.filter { $0.uptime == .hard }.count
                ),
                methodology: ReportMethodology.build(zones: zones, tolerance: tolerance),
                actions: actions,
                threatActors: Self.threatActors(
                    faced: ThreatActorLookup(model: model, catalogue: catalogue).faced(),
                    threats: assessment.threats
                ),
                history: request.history,
                historyTruncated: request.historyTruncated,
                change: request.change,
                policy: policyRules.map {
                    ReportPolicyRule(name: $0.name, asks: $0.asks, breaches: $0.breaches)
                },
                evidenceRequiredAboveLabel: model.requiresEvidenceAbove?.label,
                acceptedRisks: acceptedRisks,
                attackTrees: assessment.attackTrees,
                attackPathCount: attack.paths.count + attack.notListed.count + attack.beyond
            )
        )
    }

    /// The humans who use the system, with what they reach by name, the
    /// clients they hold with what those reach, and the actor each one is.
    static func users(
        of model: ThreatModel,
        nameOf: (ComponentId) -> String,
        actors: ThreatActorLookup
    ) -> [ReportUser] {
        model.components.compactMap { component in
            guard let facts = component.user else { return nil }
            return ReportUser(
                name: nameOf(component.id),
                role: facts.role,
                accessLabel: component.runsAs.label,
                reaches: facts.reaches.map { nameOf(ComponentId($0)) },
                clients: facts.uses.map { client in
                    ReportClient(
                        name: nameOf(ComponentId(client)),
                        reaches: model.connections
                            .filter { $0.source.value == client }
                            .map { nameOf($0.target) }
                    )
                },
                threatActorName: facts.threatActorId.flatMap {
                    actors.findById(ThreatActorId($0))?.name
                },
                isAdversary: facts.isAdversary,
                clearanceName: facts.clearanceId.flatMap { named in
                    model.clearances.first { $0.id == named }?.name
                }
            )
        }
    }

    /// The adversaries this assessment is written against, and how many of
    /// this model's threats each one performs.
    static func threatActors(
        faced: [ThreatActor],
        threats: [AssessedThreat]
    ) -> [ReportThreatActor] {
        faced.map { actor in
            ReportThreatActor(
                name: actor.name,
                capabilityLabel: actor.capability.label,
                intent: actor.intent,
                threatsPerformed: threats.filter { $0.performedByLabels.contains(actor.name) }.count
            )
        }
    }

    /// A control is counted once per distinct key, the way `SummariseRisk`
    /// counts what is offered and what is recorded.
    private static func byStatus(_ threats: [AssessedThreat]) -> [ReportCount] {
        var statusByKey: [String: String] = [:]
        for threat in threats {
            for control in threat.controls {
                statusByKey[control.key] = control.statusLabel
            }
        }

        var counts: [String: Int] = [:]
        for label in statusByKey.values {
            counts[label, default: 0] += 1
        }

        return ["Implemented", "Accepted", "Not applicable", "Not implemented"]
            .compactMap { label in
                counts[label].map { ReportCount(label: label, count: $0) }
            }
    }

    private static func threat(
        from assessed: AssessedThreat,
        tree: BoundAttackTree?,
        compensating: [ReportCompensatingControl],
        strideLabels: [String],
        impactLabels: [String],
        assetsAtRisk: [String],
        overrides: [ThreatId: ThreatOverride] = [:],
        techniqueNames: [String: String] = [:]
    ) -> ReportThreat {
        ReportThreat(
            threatId: assessed.threatId,
            name: assessed.name,
            description: assessed.description,
            severityLabel: assessed.severityLabel,
            riskScore: assessed.riskScore,
            riskLevel: assessed.riskLevel,
            strideLabels: strideLabels,
            impactLabels: impactLabels,
            assetsAtRisk: assetsAtRisk,
            mitreTechniqueIds: assessed.mitreTechniques.map(\.id),
            mitreTechniqueNames: Dictionary(
                uniqueKeysWithValues: assessed.mitreTechniques.compactMap { technique in
                    techniqueNames[technique.id].map { (technique.id, $0) }
                }
            ),
            performedByLabels: assessed.performedByLabels,
            likelihoodReason: assessed.likelihoodReason,
            scoreBeforeTree: tree?.scoreBefore,
            raisedByTree: tree?.name,
            overriddenBy: overrides[ThreatId(assessed.threatId)]?.libraryLabel,
            sourceName: assessed.source.displayName,
            sourceKind: kind(of: assessed.source),
            sourceId: assessed.source.id,
            controls: assessed.controls.map {
                ReportControl(
                    description: $0.description,
                    isImplemented: $0.isImplemented,
                    statusLabel: $0.statusLabel,
                    // Only an implemented control states evidence: a control
                    // nobody has put in place has nothing to prove.
                    evidence: $0.isImplemented
                        ? ControlProof(
                            evidence: $0.evidenceId.flatMap(ControlEvidence.init(rawValue:)),
                            reference: $0.evidenceReference ?? "",
                            verifiedOn: $0.verifiedOn.flatMap { try? GovernanceDate.read($0).get() }
                        ).says
                        : nil
                )
            },
            pathwayMitigationLabels: assessed.pathwayMitigationLabels,
            compensating: compensating,
            scoreBeforeCompensation: assessed.scoreBeforeCompensation,
            inherentScore: assessed.inherentScore,
            mitigatedByComponentLabels: assessed.mitigatedByComponentLabels,
            mitigatedByComponentReductions: assessed.mitigatedByComponentReductions,
            likelihoodLabel: assessed.likelihoodLabel,
            likelihoodRationale: assessed.likelihoodRationale,
            likelihoodFindingLabel: assessed.likelihoodFindingLabel,
            likelihoodSources: assessed.likelihoodSources,
            scoreBeforeLikelihood: assessed.scoreBeforeLikelihood,
            scoreIfAssumptionsHold: assessed.scoreIfAssumptionsHold,
            severityDecision: assessed.severityDecision.map {
                ReportSeverityDecision(
                    fromLabel: $0.fromLabel,
                    toLabel: $0.toLabel,
                    rationale: $0.rationale,
                    sources: $0.sources
                )
            }
        )
    }

    private static func kind(of source: AssessedThreatSource) -> String {
        switch source {
        case .component: "Component"
        case .connection: "Connection"
        case .zone: "Zone"
        }
    }
}
