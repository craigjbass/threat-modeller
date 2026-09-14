public protocol BuildThreatModelReportUseCase {
    func execute(_ request: BuildThreatModelReportRequest) -> BuildThreatModelReportResponse
}

public struct BuildThreatModelReportRequest: Equatable, Sendable {
    public init() {}
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

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        clock: Clock = SystemClock()
    ) {
        self.models = models
        self.catalogue = catalogue
        self.clock = clock
    }

    public func execute(_ request: BuildThreatModelReportRequest) -> BuildThreatModelReportResponse {
        let model = models.current()
        let taxonomy = catalogue.taxonomy()
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        let assessment = AssessThreatModel(models: models, catalogue: catalogue)
            .execute(AssessThreatModelRequest())
        let summary = SummariseRisk(models: models, catalogue: catalogue)
            .execute(SummariseRiskRequest())
        let leverage = AssessLeverage(models: models, catalogue: catalogue)
            .execute(AssessLeverageRequest())

        var nameById: [ComponentId: String] = [:]
        for component in model.components {
            nameById[component.id] = component.customName
                ?? lookup.findById(component.technologyId)?.name
                ?? component.technologyId.value
        }
        let nameOf: (ComponentId) -> String = { nameById[$0] ?? $0.value }

        let zoneByComponent = Dictionary(
            uniqueKeysWithValues: model.components.map { component in
                (
                    component.id,
                    ZoneContainment.zone(holding: component.centre, in: model.zones)
                )
            }
        )

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
                compensating: model.compensatingControls[
                    ThreatKey(
                        threatId: assessed.threatId,
                        sourceId: assessed.source.id
                    )
                ]?.map {
                    ReportCompensatingControl(
                        label: $0.label,
                        reducesRiskBy: $0.reducesRiskBy,
                        rationale: $0.rationale,
                        sources: $0.sources
                    )
                } ?? [],
                // The assessment names STRIDE by id. A report is read
                // by people, so it names it by label.
                strideLabels: assessed.stride.compactMap {
                    taxonomy.strideCategory(id: StrideId($0))?.label
                }
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

        let recommendations = RecommendationsReport.build(
            threats: threats,
            recommendations: model.recommendations,
            governance: model.plannedWork
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

        // Computed once so the verdict sentence and the Findings section
        // can never disagree about which threats sit above tolerance.
        let findingsCut = ReportFindingsCut.build(from: threats, tolerance: tolerance)

        // Built once so the Executive summary and the Actions section can
        // never name a different list of actions.
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

        return BuildThreatModelReportResponse(
            report: Report(
                modelName: model.name,
                catalogueTag: model.catalogueVersion?.tag ?? catalogue.version().tag,
                summary: ReportSummary(
                    totalThreats: summary.totalThreats,
                    byLevel: summary.byLevel.map { ReportCount(label: $0.label, count: $0.count) },
                    byStride: summary.byStride.map { ReportCount(label: $0.label, count: $0.count) },
                    controlsOffered: summary.controlsOffered,
                    controlsRecorded: summary.controlsRecorded,
                    byControlStatus: Self.byStatus(assessment.threats)
                ),
                components: model.components.map { component in
                    ReportComponent(
                        id: component.id.value,
                        name: nameById[component.id] ?? component.technologyId.value,
                        technologyId: component.technologyId.value,
                        categoryId: lookup.findById(component.technologyId)?.category.value ?? "",
                        sensitivityLabel: component.effectiveSensitivity.label,
                        zoneName: zoneByComponent[component.id]??.displayName,
                        assetNames: component.assets.map(\.name),
                        privilegeLabel: component.runsAs.label
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
                assumedMitigations: assumedMitigations,
                findings: findingsCut,
                toleranceLabel: tolerance.label,
                executiveSummary: ReportExecutiveSummary.build(
                    threats: threats,
                    recommendations: recommendations,
                    tolerance: tolerance,
                    findings: findingsCut,
                    actions: actions,
                    acceptedRisks: acceptedRisks
                ),
                methodology: ReportMethodology.build(zones: zones, tolerance: tolerance),
                actions: actions,
                threatActors: Self.threatActors(
                    faced: ThreatActorLookup(model: model, catalogue: catalogue).faced(),
                    threats: assessment.threats
                ),
                acceptedRisks: acceptedRisks,
                attackTrees: assessment.attackTrees,
                attackPathCount: attack.paths.count + attack.notListed.count + attack.beyond
            )
        )
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
        strideLabels: [String]
    ) -> ReportThreat {
        ReportThreat(
            threatId: assessed.threatId,
            name: assessed.name,
            description: assessed.description,
            severityLabel: assessed.severityLabel,
            riskScore: assessed.riskScore,
            riskLevel: assessed.riskLevel,
            strideLabels: strideLabels,
            mitreTechniqueIds: assessed.mitreTechniques.map(\.id),
            performedByLabels: assessed.performedByLabels,
            likelihoodReason: assessed.likelihoodReason,
            scoreBeforeTree: tree?.scoreBefore,
            raisedByTree: tree?.name,
            sourceName: assessed.source.displayName,
            sourceKind: kind(of: assessed.source),
            sourceId: assessed.source.id,
            controls: assessed.controls.map {
                ReportControl(
                    description: $0.description,
                    isImplemented: $0.isImplemented,
                    statusLabel: $0.statusLabel
                )
            },
            pathwayMitigationLabels: assessed.pathwayMitigationLabels,
            compensating: compensating,
            scoreBeforeCompensation: assessed.scoreBeforeCompensation,
            inherentScore: assessed.inherentScore,
            mitigatedByComponentLabels: assessed.mitigatedByComponentLabels,
            likelihoodLabel: assessed.likelihoodLabel,
            likelihoodRationale: assessed.likelihoodRationale,
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
