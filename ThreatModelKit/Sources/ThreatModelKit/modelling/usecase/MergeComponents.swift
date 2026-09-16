public protocol MergeComponentsUseCase {
    func execute(_ request: MergeComponentsRequest) -> MergeComponentsResponse
}

/// The bytes one file held at one moment, or nil when the file was absent.
public struct FileSnapshot: Equatable, Sendable {
    public let path: String
    public let text: String?

    public init(path: String, text: String?) {
        self.path = path
        self.text = text
    }
}

/// What the sheet resolved. Every attribute is the value that stays, so the
/// use case decides nothing about them.
public struct MergeComponentsRequest: Equatable, Sendable {
    /// The open project's root, or nil for a model no project holds. Nil
    /// changes the model alone and writes no file.
    public let root: String?
    /// The system's own file name, or nil with `root`.
    public let systemName: String?
    public let survivorId: String
    public let sourceIds: [String]
    public let technologyId: String
    public let shape: String?
    public let name: String?
    public let sensitivity: String
    public let runsAs: String
    public let holds: [String]
    public let zoneId: String?
    public let status: String
    public let tags: [String]
    public let providedBy: String?

    public init(
        root: String? = nil,
        systemName: String? = nil,
        survivorId: String,
        sourceIds: [String],
        technologyId: String,
        shape: String? = nil,
        name: String? = nil,
        sensitivity: String,
        runsAs: String,
        holds: [String] = [],
        zoneId: String? = nil,
        status: String = ComponentStatus.default.rawValue,
        tags: [String] = [],
        providedBy: String? = nil
    ) {
        self.root = root
        self.systemName = systemName
        self.survivorId = survivorId
        self.sourceIds = sourceIds
        self.technologyId = technologyId
        self.shape = shape
        self.name = name
        self.sensitivity = sensitivity
        self.runsAs = runsAs
        self.holds = holds
        self.zoneId = zoneId
        self.status = status
        self.tags = tags
        self.providedBy = providedBy
    }
}

public enum MergeComponentsResponse: Equatable, Sendable {
    public struct Merged: Equatable, Sendable {
        /// The flows dropped because both ends became the survivor, in model
        /// order.
        public let droppedFlowIds: [String]
        /// The flows that joined into another flow, in model order.
        public let joinedFlowIds: [String]
        /// Each answer dropped, as `<threat>@<kind>:<id>`, sorted.
        public let droppedAnswers: [String]
        /// The bytes of every file the merge read, before and after the
        /// rewrite, so Undo and Redo put them back.
        public let filesBefore: [FileSnapshot]
        public let filesAfter: [FileSnapshot]

        public init(
            droppedFlowIds: [String],
            joinedFlowIds: [String],
            droppedAnswers: [String],
            filesBefore: [FileSnapshot] = [],
            filesAfter: [FileSnapshot] = []
        ) {
            self.droppedFlowIds = droppedFlowIds
            self.joinedFlowIds = joinedFlowIds
            self.droppedAnswers = droppedAnswers
            self.filesBefore = filesBefore
            self.filesAfter = filesAfter
        }
    }

    case merged(Merged)
    case tooFewComponents
    case unknownComponent(componentId: String)
    case userCannotMerge(componentId: String)
    case unknownTechnology
    case unknownShape
    case unknownSensitivity
    case unknownPrivilegeLevel
    case unknownAsset
    case unknownZone
    case unknownStatus
    case unknownThirdParty
    case noSuchSystem
    case cannotWrite(reason: String)
}

/// Joins two or more components into one, as
/// `docs/superpowers/specs/2026-09-16-merge-components-design.md` decides.
///
/// The survivor keeps its identifier and takes the resolved attributes. Every
/// flow, edge, reach, answer and attack tree step of a source moves to the
/// survivor. The controls files and the attack tree files are rewritten
/// through their one writer each, before the model changes, so a write that
/// fails leaves the model as it was. The model change is one `mutate`.
public struct MergeComponents: MergeComponentsUseCase {
    private let models: ThreatModelGateway
    private let catalogue: TechnologyCatalogue
    private let projects: ProjectSourceGateway
    private let controlsSources: ControlsSourceGateway
    private let attackTreeSources: AttackTreeSourceGateway

    public init(
        models: ThreatModelGateway,
        catalogue: TechnologyCatalogue,
        projects: ProjectSourceGateway,
        controlsSources: ControlsSourceGateway,
        attackTreeSources: AttackTreeSourceGateway
    ) {
        self.models = models
        self.catalogue = catalogue
        self.projects = projects
        self.controlsSources = controlsSources
        self.attackTreeSources = attackTreeSources
    }

    public func execute(_ request: MergeComponentsRequest) -> MergeComponentsResponse {
        guard let sensitivity = DataSensitivity.validated(
            request.sensitivity,
            in: catalogue.classifications()
        ) else {
            return .unknownSensitivity
        }
        guard let runsAs = PrivilegeLevel(rawValue: request.runsAs) else {
            return .unknownPrivilegeLevel
        }
        var shape: DiagramShape?
        if let word = request.shape {
            guard let picked = DiagramShape(rawValue: word) else { return .unknownShape }
            shape = picked
        }
        guard let status = ComponentStatus(rawValue: request.status) else {
            return .unknownStatus
        }

        let model = models.current()
        guard request.sourceIds.isEmpty == false else { return .tooFewComponents }
        let survivor = ComponentId(request.survivorId)
        guard let kept = model.component(survivor) else {
            return .unknownComponent(componentId: request.survivorId)
        }
        guard kept.isUser == false else { return .userCannotMerge(componentId: request.survivorId) }
        var sources: [ComponentId] = []
        for raw in request.sourceIds {
            let id = ComponentId(raw)
            guard id != survivor, sources.contains(id) == false,
                  let source = model.component(id) else {
                return .unknownComponent(componentId: raw)
            }
            guard source.isUser == false else { return .userCannotMerge(componentId: raw) }
            sources.append(id)
        }

        let technologyId = TechnologyId(request.technologyId)
        let lookup = TechnologyLookup(model: model, catalogue: catalogue)
        guard lookup.findById(technologyId) != nil else { return .unknownTechnology }
        let declaredAssets = Set(model.systemAssets.map(\.id))
        guard request.holds.allSatisfy(declaredAssets.contains) else { return .unknownAsset }
        if let zoneId = request.zoneId, model.zone(ZoneId(zoneId)) == nil {
            return .unknownZone
        }
        if let providedBy = request.providedBy,
           model.thirdParties.contains(where: { $0.id == providedBy }) == false {
            return .unknownThirdParty
        }

        let resolved = ComponentMerge.Resolved(
            technologyId: technologyId,
            shape: shape,
            name: request.name?.trimmingWhitespace(),
            sensitivity: sensitivity,
            runsAs: runsAs,
            holds: request.holds,
            zoneId: request.zoneId.map(ZoneId.init),
            status: status,
            tags: request.tags,
            providedBy: request.providedBy
        )
        let raised = Set(lookup.threatsFor(technologyId: technologyId).map(\.id))

        // The plan, on a copy, so the files are written from what the model
        // will hold and the model changes only once every write succeeded.
        var planned = model
        let plan = ComponentMerge.apply(
            to: &planned,
            survivor: survivor,
            sources: sources,
            resolved: resolved,
            raised: raised
        )

        var filesBefore: [FileSnapshot] = []
        var filesAfter: [FileSnapshot] = []
        var droppedInFiles: Set<String> = []
        if let root = request.root, let systemName = request.systemName {
            switch rewriteFiles(
                root: root,
                systemName: systemName,
                survivor: survivor,
                sources: Set(sources),
                plan: plan,
                raised: raised
            ) {
            case .written(let before, let after, let dropped):
                filesBefore = before
                filesAfter = after
                droppedInFiles = dropped
            case .noSuchSystem:
                return .noSuchSystem
            case .cannotWrite(let reason):
                return .cannotWrite(reason: reason)
            }
        }

        let applied = models.mutate(label: ChangeLabel.mergeComponents) { model in
            ComponentMerge.apply(
                to: &model,
                survivor: survivor,
                sources: sources,
                resolved: resolved,
                raised: raised
            )
        }

        return .merged(
            MergeComponentsResponse.Merged(
                droppedFlowIds: applied.droppedFlowIds,
                joinedFlowIds: applied.joinedFlowIds,
                droppedAnswers: applied.droppedAnswers.union(droppedInFiles).sorted(),
                filesBefore: filesBefore,
                filesAfter: filesAfter
            )
        )
    }

    // MARK: the files

    private enum Rewrite {
        case written(before: [FileSnapshot], after: [FileSnapshot], dropped: Set<String>)
        case noSuchSystem
        case cannotWrite(reason: String)
    }

    /// Rewrites every controls file and every attack tree file of the
    /// system. A file the rewrite does not change is not written.
    private func rewriteFiles(
        root: String,
        systemName: String,
        survivor: ComponentId,
        sources: Set<ComponentId>,
        plan: ComponentMerge.Report,
        raised: Set<ThreatId>
    ) -> Rewrite {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: root)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        guard let system = layout.systems.first(where: { $0.name == systemName }) else {
            return .noSuchSystem
        }

        var controls: [(path: String, text: String, source: ControlsSource)] = []
        for path in system.controlsPaths where projects.exists(path: path) {
            guard let text = try? projects.read(path: path) else {
                return .cannotWrite(reason: "\(path) could not be read")
            }
            let read = controlsSources.read(text)
            guard let source = read.source, read.hasErrors == false else {
                return .cannotWrite(
                    reason: read.diagnostics.first?.described(in: path) ?? "\(path) does not parse"
                )
            }
            controls.append((path, text, source))
        }
        var trees: [(path: String, text: String, source: AttackTreeSource)] = []
        for path in system.attackTreePaths where projects.exists(path: path) {
            guard let text = try? projects.read(path: path) else {
                return .cannotWrite(reason: "\(path) could not be read")
            }
            let read = attackTreeSources.read(text)
            guard let source = read.source, read.hasErrors == false else {
                return .cannotWrite(
                    reason: read.diagnostics.first?.described(in: path) ?? "\(path) does not parse"
                )
            }
            trees.append((path, text, source))
        }

        // A key any file already holds, on an element that is not moving,
        // wins over a moved stanza with the same key.
        var held: Set<String> = []
        for file in controls {
            for answer in file.source.answers
            where ComponentMerge.moves(answer, sources: sources, plan: plan) == false {
                held.insert(answer.key.value)
            }
        }

        var dropped: Set<String> = []
        var writes: [(path: String, text: String)] = []
        var before: [FileSnapshot] = []
        var after: [FileSnapshot] = []

        for file in controls {
            var answers: [SourceThreatAnswer] = []
            for answer in file.source.answers {
                guard let moved = ComponentMerge.moved(
                    answer,
                    survivor: survivor,
                    sources: sources,
                    plan: plan
                ) else {
                    answers.append(answer)
                    continue
                }
                guard let moved else {
                    dropped.insert(answer.key.value)
                    continue
                }
                let raisedOnSurvivor = moved.sourceKind != "component"
                    || raised.contains(ThreatId(moved.threatId))
                guard raisedOnSurvivor, held.insert(moved.key.value).inserted else {
                    dropped.insert(answer.key.value)
                    continue
                }
                answers.append(moved)
            }
            let text = answers == file.source.answers
                ? file.text
                : controlsSources.write(
                    ControlsSource(
                        systemName: file.source.systemName,
                        catalogueTag: file.source.catalogueTag,
                        riskTolerance: file.source.riskTolerance,
                        answers: answers,
                        trees: file.source.trees
                    )
                )
            before.append(FileSnapshot(path: file.path, text: file.text))
            after.append(FileSnapshot(path: file.path, text: text))
            if text != file.text { writes.append((file.path, text)) }
        }

        for file in trees {
            let rewritten = file.source.trees.map {
                ComponentMerge.rewritten($0, survivor: survivor, sources: sources, pairs: plan.pairs)
            }
            let text = rewritten == file.source.trees
                ? file.text
                : attackTreeSources.write(
                    AttackTreeSource(
                        systemName: file.source.systemName,
                        catalogueTag: file.source.catalogueTag,
                        trees: rewritten
                    )
                )
            before.append(FileSnapshot(path: file.path, text: file.text))
            after.append(FileSnapshot(path: file.path, text: text))
            if text != file.text { writes.append((file.path, text)) }
        }

        for write in writes {
            do {
                try projects.write(write.text, to: write.path)
            } catch {
                return .cannotWrite(reason: String(describing: error))
            }
        }
        return .written(before: before, after: after, dropped: dropped)
    }
}

/// The merge on the model, as one pure change, so the file rewrite and the
/// `mutate` read one rule.
enum ComponentMerge {
    struct Resolved {
        let technologyId: TechnologyId
        let shape: DiagramShape?
        let name: String?
        let sensitivity: DataSensitivity
        let runsAs: PrivilegeLevel
        let holds: [String]
        let zoneId: ZoneId?
        let status: ComponentStatus
        let tags: [String]
        let providedBy: String?
    }

    struct Report {
        var droppedFlowIds: [String] = []
        var joinedFlowIds: [String] = []
        var droppedAnswers: Set<String> = []
        /// Each moved flow's identifier before and after, for the flows whose
        /// identifier changed.
        var flowIds: [String: String] = [:]
        /// Each moved flow's pair before and after, as `<source>-><target>`.
        var pairs: [String: String] = [:]
        /// The pairs of the flows that were dropped.
        var droppedPairs: Set<String> = []
        /// The identifiers of the flows that were dropped.
        var droppedFlowIdSet: Set<String> = []
    }

    static func apply(
        to model: inout ThreatModel,
        survivor: ComponentId,
        sources: [ComponentId],
        resolved: Resolved,
        raised: Set<ThreatId>
    ) -> Report {
        var report = Report()
        let doomed = Set(sources)
        func end(_ id: ComponentId) -> ComponentId { doomed.contains(id) ? survivor : id }

        // The survivor.
        guard let index = model.components.firstIndex(where: { $0.id == survivor }) else { return report }
        var kept = model.components[index]
        kept.technologyId = resolved.technologyId
        kept.shape = resolved.shape
        kept.customName = resolved.name.flatMap { $0.isEmpty ? nil : $0 }
        kept.sensitivity = resolved.sensitivity
        kept.runsAs = resolved.runsAs
        kept.holds = resolved.holds
        kept.zoneId = resolved.zoneId
        kept.status = resolved.status
        kept.tags = resolved.tags
        kept.providedBy = resolved.providedBy
        for source in model.components where doomed.contains(source.id) {
            for asset in source.assets where kept.assets.contains(where: { $0.name == asset.name }) == false {
                kept.assets.append(asset)
            }
        }
        model.components[index] = kept
        model.components.removeAll { doomed.contains($0.id) }

        // The flows.
        var flows: [Connection] = []
        var byPair: [String: Int] = [:]
        for flow in model.connections {
            let source = end(flow.source)
            let target = end(flow.target)
            let oldPair = "\(flow.source.value)->\(flow.target.value)"
            let newPair = "\(source.value)->\(target.value)"
            let moved = source != flow.source || target != flow.target
            if source == target {
                report.droppedFlowIds.append(flow.id.value)
                report.droppedFlowIdSet.insert(flow.id.value)
                report.droppedPairs.insert(oldPair)
                continue
            }
            let id = moved && flow.id.value == oldPair ? ConnectionId(newPair) : flow.id
            if let existing = byPair[newPair] {
                let stays = flows[existing]
                flows[existing] = Connection(
                    id: stays.id,
                    source: stays.source,
                    target: stays.target,
                    kind: stays.kind,
                    description: stays.description,
                    carries: union(stays.carries, flow.carries),
                    tags: union(stays.tags, flow.tags)
                )
                report.joinedFlowIds.append(flow.id.value)
                if flow.id != stays.id { report.flowIds[flow.id.value] = stays.id.value }
                if moved { report.pairs[oldPair] = newPair }
                continue
            }
            byPair[newPair] = flows.count
            flows.append(
                Connection(
                    id: id,
                    source: source,
                    target: target,
                    kind: flow.kind,
                    description: flow.description,
                    carries: flow.carries,
                    tags: flow.tags
                )
            )
            if id != flow.id { report.flowIds[flow.id.value] = id.value }
            if moved { report.pairs[oldPair] = newPair }
        }
        model.connections = flows

        // The mitigates edges.
        var edges: [MitigatesEdge] = []
        var edgeByPair: [String: Int] = [:]
        for edge in model.mitigatesEdges {
            let source = end(edge.source)
            let target = end(edge.target)
            guard source != target else { continue }
            let pair = "\(source.value)->\(target.value)"
            if let existing = edgeByPair[pair] {
                edges[existing].threatIds = union(edges[existing].threatIds, edge.threatIds)
                continue
            }
            var moved = edge
            moved.source = source
            moved.target = target
            edgeByPair[pair] = edges.count
            edges.append(moved)
        }
        model.mitigatesEdges = edges

        // The users.
        for index in model.components.indices where model.components[index].user != nil {
            let reaches = model.components[index].user?.reaches ?? []
            model.components[index].user?.reaches = union([], reaches.map { end(ComponentId($0)).value })
        }

        // The answers.
        let prefixes = Dictionary(
            uniqueKeysWithValues: sources.map {
                (ControlIdentity.componentPrefix($0), ControlIdentity.componentPrefix(survivor))
            }
        )
        model.controlStatuses = rekeyed(
            model.controlStatuses, keyed: \.value, prefixes: prefixes, make: ControlKey.init,
            describe: describeControl, report: &report
        )
        model.controlProofs = rekeyed(
            model.controlProofs, keyed: \.value, prefixes: prefixes, make: ControlKey.init,
            describe: describeControl, report: &report
        )
        let overridePrefixes = Dictionary(
            uniqueKeysWithValues: sources.map {
                (SeverityOverrideKey.componentPrefix($0), SeverityOverrideKey.componentPrefix(survivor))
            }
        )
        model.severityOverrides = rekeyed(
            model.severityOverrides, keyed: \.value, prefixes: overridePrefixes, make: SeverityOverrideKey.init,
            describe: describeOverride, report: &report
        )

        var suffixes: [String: String] = [:]
        for source in sources { suffixes["@component:\(source.value)"] = "@component:\(survivor.value)" }
        for (old, new) in report.flowIds { suffixes["@connection:\(old)"] = "@connection:\(new)" }
        let droppedSuffixes = Set(report.droppedFlowIdSet.map { "@connection:\($0)" })
        model.compensatingControls = rekeyed(model.compensatingControls, suffixes: suffixes, dropped: droppedSuffixes, report: &report)
        model.recommendations = rekeyed(model.recommendations, suffixes: suffixes, dropped: droppedSuffixes, report: &report)
        model.likelihoodFindings = rekeyed(model.likelihoodFindings, suffixes: suffixes, dropped: droppedSuffixes, report: &report)
        model.severityDecisions = rekeyed(model.severityDecisions, suffixes: suffixes, dropped: droppedSuffixes, report: &report)
        model.impactOverrides = rekeyed(model.impactOverrides, suffixes: suffixes, dropped: droppedSuffixes, report: &report)
        model.acceptedRisks = rekeyed(model.acceptedRisks, suffixes: suffixes, dropped: droppedSuffixes, report: &report)
        model.plannedWork = rekeyed(model.plannedWork, suffixes: suffixes, dropped: droppedSuffixes, report: &report)

        // An answer on a threat the resolved technology does not raise.
        let survivorPrefix = ControlIdentity.componentPrefix(survivor)
        model.controlStatuses = model.controlStatuses.filter { key, _ in
            keepsControl(key, prefix: survivorPrefix, raised: raised, report: &report)
        }
        model.controlProofs = model.controlProofs.filter { key, _ in
            keepsControl(key, prefix: survivorPrefix, raised: raised, report: &report)
        }
        let survivorOverride = SeverityOverrideKey.componentPrefix(survivor)
        model.severityOverrides = model.severityOverrides.filter { key, _ in
            guard key.value.hasPrefix(survivorOverride) else { return true }
            let threatId = ThreatId(String(key.value.dropFirst(survivorOverride.count)))
            guard raised.contains(threatId) == false else { return true }
            report.droppedAnswers.insert(describeOverride(key))
            return false
        }
        let survivorSource = "component:\(survivor.value)"
        model.compensatingControls = model.compensatingControls.filter { key, _ in keeps(key, source: survivorSource, raised: raised, report: &report) }
        model.recommendations = model.recommendations.filter { key, _ in keeps(key, source: survivorSource, raised: raised, report: &report) }
        model.likelihoodFindings = model.likelihoodFindings.filter { key, _ in keeps(key, source: survivorSource, raised: raised, report: &report) }
        model.severityDecisions = model.severityDecisions.filter { key, _ in keeps(key, source: survivorSource, raised: raised, report: &report) }
        model.impactOverrides = model.impactOverrides.filter { key, _ in keeps(key, source: survivorSource, raised: raised, report: &report) }
        model.acceptedRisks = model.acceptedRisks.filter { key, _ in keeps(key, source: survivorSource, raised: raised, report: &report) }
        model.plannedWork = model.plannedWork.filter { key, _ in keeps(key, source: survivorSource, raised: raised, report: &report) }

        // The attack trees.
        model.attackTrees = model.attackTrees.map {
            rewritten($0, survivor: survivor, sources: doomed, pairs: report.pairs)
        }

        return report
    }

    // MARK: the controls file

    /// True when the stanza names a source, or a flow the merge moved or
    /// dropped.
    static func moves(_ answer: SourceThreatAnswer, sources: Set<ComponentId>, plan: Report) -> Bool {
        switch answer.sourceKind {
        case "component":
            return sources.contains(ComponentId(answer.sourceId))
        case "flow":
            return plan.pairs[answer.sourceId] != nil || plan.droppedPairs.contains(answer.sourceId)
        default:
            return false
        }
    }

    /// The stanza on its new key. `.some(nil)` is a stanza the merge drops,
    /// and `nil` is a stanza the merge does not touch.
    static func moved(
        _ answer: SourceThreatAnswer,
        survivor: ComponentId,
        sources: Set<ComponentId>,
        plan: Report
    ) -> SourceThreatAnswer?? {
        guard moves(answer, sources: sources, plan: plan) else { return nil }
        let sourceId: String
        switch answer.sourceKind {
        case "component":
            sourceId = survivor.value
        default:
            guard let pair = plan.pairs[answer.sourceId] else { return .some(nil) }
            sourceId = pair
        }
        return .some(
            SourceThreatAnswer(
                threatId: answer.threatId,
                sourceKind: answer.sourceKind,
                sourceId: sourceId,
                severityLabel: answer.severityLabel,
                score: answer.score,
                likelihood: answer.likelihood,
                severityDecision: answer.severityDecision,
                impacts: answer.impacts,
                controls: answer.controls,
                compensating: answer.compensating,
                recommendations: answer.recommendations,
                isStale: answer.isStale
            )
        )
    }

    // MARK: the attack trees

    static func rewritten(
        _ tree: SourceAttackTree,
        survivor: ComponentId,
        sources: Set<ComponentId>,
        pairs: [String: String]
    ) -> SourceAttackTree {
        SourceAttackTree(
            id: tree.id,
            name: tree.name,
            description: tree.description,
            raisesRiskBy: tree.raisesRiskBy,
            goal: rewritten(tree.goal, survivor: survivor, sources: sources, pairs: pairs),
            root: rewritten(tree.root, survivor: survivor, sources: sources, pairs: pairs)
        )
    }

    private static func rewritten(
        _ node: SourceTreeNode,
        survivor: ComponentId,
        sources: Set<ComponentId>,
        pairs: [String: String]
    ) -> SourceTreeNode {
        switch node {
        case .step(let step):
            .step(
                SourceTreeStep(
                    target: rewritten(step.target, survivor: survivor, sources: sources, pairs: pairs),
                    note: step.note
                )
            )
        case .all(let children):
            .all(children.map { rewritten($0, survivor: survivor, sources: sources, pairs: pairs) })
        case .any(let children):
            .any(children.map { rewritten($0, survivor: survivor, sources: sources, pairs: pairs) })
        case .then(let links):
            .then(links.map { rewritten($0, survivor: survivor, sources: sources, pairs: pairs) })
        }
    }

    private static func rewritten(
        _ target: SourceTreeTarget,
        survivor: ComponentId,
        sources: Set<ComponentId>,
        pairs: [String: String]
    ) -> SourceTreeTarget {
        let sourceId: String
        switch target.sourceKind {
        case "component" where sources.contains(ComponentId(target.sourceId)):
            sourceId = survivor.value
        case "flow":
            sourceId = pairs[target.sourceId] ?? target.sourceId
        default:
            sourceId = target.sourceId
        }
        return SourceTreeTarget(threatId: target.threatId, sourceKind: target.sourceKind, sourceId: sourceId)
    }

    // MARK: the keys

    /// A prefix-keyed map with every source key read onto the survivor. A key
    /// that is not moving wins over a moved key; a moved key that loses is
    /// reported. Moved keys are read in sorted order, so the report is the
    /// same every run.
    private static func rekeyed<Key: Hashable, Value>(
        _ map: [Key: Value],
        keyed value: KeyPath<Key, String>,
        prefixes: [String: String],
        make: (String) -> Key,
        describe: (Key) -> String,
        report: inout Report
    ) -> [Key: Value] {
        var result: [Key: Value] = [:]
        var moving: [(Key, Value)] = []
        for (key, held) in map {
            if prefixes.keys.contains(where: { key[keyPath: value].hasPrefix($0) }) {
                moving.append((key, held))
            } else {
                result[key] = held
            }
        }
        for (key, held) in moving.sorted(by: { $0.0[keyPath: value] < $1.0[keyPath: value] }) {
            let old = prefixes.keys.first { key[keyPath: value].hasPrefix($0) } ?? ""
            let fresh = make(prefixes[old, default: old] + key[keyPath: value].dropFirst(old.count))
            if result[fresh] == nil {
                result[fresh] = held
            } else {
                report.droppedAnswers.insert(describe(key))
            }
        }
        return result
    }

    /// A threat-keyed map with every source key read onto the survivor, and
    /// every moved flow's key read onto the flow's new identifier. A key on a
    /// dropped flow is dropped and reported.
    private static func rekeyed<Value>(
        _ map: [ThreatKey: Value],
        suffixes: [String: String],
        dropped: Set<String>,
        report: inout Report
    ) -> [ThreatKey: Value] {
        var result: [ThreatKey: Value] = [:]
        var moving: [(ThreatKey, Value)] = []
        for (key, held) in map {
            if dropped.contains(where: { key.value.hasSuffix($0) }) {
                report.droppedAnswers.insert(key.value)
            } else if suffixes.keys.contains(where: { key.value.hasSuffix($0) }) {
                moving.append((key, held))
            } else {
                result[key] = held
            }
        }
        for (key, held) in moving.sorted(by: { $0.0.value < $1.0.value }) {
            let old = suffixes.keys.first { key.value.hasSuffix($0) } ?? ""
            let fresh = ThreatKey(key.value.dropLast(old.count) + suffixes[old, default: old])
            if result[fresh] == nil {
                result[fresh] = held
            } else {
                report.droppedAnswers.insert(key.value)
            }
        }
        return result
    }

    private static func keepsControl(
        _ key: ControlKey,
        prefix: String,
        raised: Set<ThreatId>,
        report: inout Report
    ) -> Bool {
        guard key.value.hasPrefix(prefix), let read = ControlIdentity.read(key) else { return true }
        guard raised.contains(read.threatId) == false else { return true }
        report.droppedAnswers.insert(describeControl(key))
        return false
    }

    private static func keeps(
        _ key: ThreatKey,
        source: String,
        raised: Set<ThreatId>,
        report: inout Report
    ) -> Bool {
        let halves = key.value.components(separatedBy: "@")
        guard halves.count == 2, halves[1] == source else { return true }
        guard raised.contains(ThreatId(halves[0])) == false else { return true }
        report.droppedAnswers.insert(key.value)
        return false
    }

    /// A control key said the way a threat key is said:
    /// `<threat>@component:<id>`.
    private static func describeControl(_ key: ControlKey) -> String {
        let segments = key.value.components(separatedBy: ":")
        guard segments.count >= 3, let read = ControlIdentity.read(key) else { return key.value }
        return "\(read.threatId.value)@component:\(segments[1])"
    }

    private static func describeOverride(_ key: SeverityOverrideKey) -> String {
        let halves = key.value.components(separatedBy: "::")
        guard halves.count == 2 else { return key.value }
        let segments = halves[0].components(separatedBy: ":")
        guard segments.count == 2 else { return key.value }
        return "\(halves[1])@component:\(segments[1])"
    }

    private static func union(_ first: [String], _ second: [String]) -> [String] {
        var seen: Set<String> = []
        return (first + second).filter { seen.insert($0).inserted }
    }

    private static func union(_ first: [ThreatId], _ second: [ThreatId]) -> [ThreatId] {
        var seen: Set<ThreatId> = []
        return (first + second).filter { seen.insert($0).inserted }
    }
}
