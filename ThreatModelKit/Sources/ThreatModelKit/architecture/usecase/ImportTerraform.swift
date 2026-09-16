public protocol ImportTerraformUseCase {
    func execute(_ request: ImportTerraformRequest) -> ImportTerraformResponse
}

public struct ImportTerraformRequest: Equatable, Sendable {
    /// The JSON `terraform show -json` writes.
    public let stateText: String
    /// The `.arch` file as it stands, or nil when there is none yet.
    public let architectureText: String?
    /// What the system is called when the import writes a new file.
    public let systemName: String

    public init(stateText: String, architectureText: String? = nil, systemName: String) {
        self.stateText = stateText
        self.architectureText = architectureText
        self.systemName = systemName
    }
}

public enum ImportTerraformResponse: Equatable, Sendable {
    /// The file to write, what changed, and the resource types this
    /// application does not map.
    case imported(
        text: String,
        added: [String],
        removed: [String],
        components: Int,
        zones: Int,
        flows: Int,
        unmapped: [(type: String, count: Int)]
    )
    /// The state could not be read as JSON.
    case unreadableState
    /// The state holds nothing this application maps.
    case nothingToImport(unmapped: [(type: String, count: Int)])
    /// The `.arch` file that is there does not parse, so nothing is written
    /// over it.
    case refused(diagnostics: [Diagnostic])

    public static func == (left: ImportTerraformResponse, right: ImportTerraformResponse) -> Bool {
        switch (left, right) {
        case (.unreadableState, .unreadableState):
            true
        case (.refused(let first), .refused(let second)):
            first == second
        case (.nothingToImport(let first), .nothingToImport(let second)):
            first.map(\.type) == second.map(\.type) && first.map(\.count) == second.map(\.count)
        case (
            .imported(let text, let added, let removed, let components, let zones, let flows, _),
            .imported(
                let otherText, let otherAdded, let otherRemoved,
                let otherComponents, let otherZones, let otherFlows, _
            )
        ):
            text == otherText && added == otherAdded && removed == otherRemoved
                && components == otherComponents && zones == otherZones && flows == otherFlows
        default:
            false
        }
    }
}

/// Draws what a Terraform state holds.
///
/// The mapping, and what an import may not decide, are stated in
/// `docs/superpowers/specs/2026-09-15-terraform-import-design.md`. Every
/// element this writes states `source = "terraform"`, so a later import knows
/// what it owns: an element a person wrote is never removed and never
/// changed.
public struct ImportTerraform: ImportTerraformUseCase {
    /// The word an imported element states.
    public static let sourceWord = "terraform"

    private let sources: ArchitectureSourceGateway

    public init(sources: ArchitectureSourceGateway) {
        self.sources = sources
    }

    public func execute(_ request: ImportTerraformRequest) -> ImportTerraformResponse {
        guard let state = TerraformState.read(request.stateText) else { return .unreadableState }

        var unmappedCounts: [String: Int] = [:]
        for resource in state.resources
        where TerraformMapping.technology(of: resource.type) == nil
            && TerraformMapping.isZone(resource.type) == false
            && TerraformMapping.flowTypes.contains(resource.type) == false {
            unmappedCounts[resource.type, default: 0] += 1
        }
        let unmapped = unmappedCounts
            .map { (type: $0.key, count: $0.value) }
            .sorted { $0.type < $1.type }

        // What the file already holds. A file that does not parse stops the
        // import: writing over it would take a person's work away.
        var held: ArchitectureSource?
        if let text = request.architectureText, text.isEmpty == false {
            let read = sources.read(text)
            guard let source = read.source, read.hasErrors == false else {
                return .refused(diagnostics: read.diagnostics)
            }
            held = source
        }

        let drawn = Self.draw(state, named: held?.systemName ?? request.systemName)
        guard drawn.components.isEmpty == false || drawn.zones.isEmpty == false else {
            return .nothingToImport(unmapped: unmapped)
        }

        let merged = Self.merge(drawn, into: held)
        return .imported(
            text: sources.write(merged.source),
            added: merged.added,
            removed: merged.removed,
            components: drawn.components.count + drawn.zones.flatMap(\.components).count,
            zones: drawn.zones.count,
            flows: drawn.flows.count,
            unmapped: unmapped
        )
    }

    // MARK: what the state draws

    /// The state as an architecture of its own, before anything is merged.
    static func draw(_ state: TerraformState, named name: String) -> ArchitectureSource {
        // A network states an id, and a component names that id, so the id
        // finds the zone the component sits in.
        var zoneIdByStateId: [String: String] = [:]
        var zones: [String: SourceZone] = [:]
        var zoneOrder: [String] = []

        for resource in state.resources where TerraformMapping.isZone(resource.type) {
            let id = TerraformMapping.identifier(resource.address)
            zones[id] = SourceZone(
                id: id,
                kind: TerraformMapping.zoneKind(of: resource),
                network: TerraformMapping.network(of: resource.type),
                name: resource.values["name"] ?? resource.name,
                source: sourceWord
            )
            zoneOrder.append(id)
            if let stateId = resource.id { zoneIdByStateId[stateId] = id }
        }

        // Which security group each component holds, so an ingress rule can
        // say which two elements a flow joins.
        var componentsByGroup: [String: [String]] = [:]
        var componentZone: [String: String] = [:]
        var components: [SourceComponent] = []

        for resource in state.resources {
            guard let technology = TerraformMapping.technology(of: resource.type) else { continue }
            let id = TerraformMapping.identifier(resource.address)

            for key in TerraformMapping.zoneKeys {
                guard let named = resource.values[key], let zoneId = zoneIdByStateId[named] else {
                    continue
                }
                componentZone[id] = zoneId
                break
            }
            for key in TerraformMapping.securityGroupKeys {
                for group in resource.lists[key] ?? [] {
                    componentsByGroup[group, default: []].append(id)
                }
            }
            // A Google resource states its tags rather than a group id.
            for tag in resource.lists["tags"] ?? [] {
                componentsByGroup["tag:\(tag)", default: []].append(id)
            }

            components.append(
                SourceComponent(
                    id: id,
                    technologyId: technology,
                    name: resource.values["name"] ?? resource.name,
                    source: sourceWord
                )
            )
        }

        // A rule naming a group on each side states a flow. A rule naming an
        // address range names nothing this model draws.
        var flows: [SourceFlow] = []
        var seen: Set<String> = []
        for resource in state.resources {
            let ingress = resource.type == "aws_security_group_rule"
                && resource.values["type"] == "ingress"
            let firewall = resource.type == "google_compute_firewall"
            guard ingress || firewall else { continue }

            let targets: [String]
            let origins: [String]
            if ingress {
                targets = componentsByGroup[resource.values["security_group_id"] ?? ""] ?? []
                origins = componentsByGroup[resource.values["source_security_group_id"] ?? ""] ?? []
            } else {
                targets = (resource.lists["target_tags"] ?? []).flatMap {
                    componentsByGroup["tag:\($0)"] ?? []
                }
                origins = (resource.lists["source_tags"] ?? []).flatMap {
                    componentsByGroup["tag:\($0)"] ?? []
                }
            }

            for origin in origins {
                for target in targets where origin != target {
                    guard seen.insert("\(origin)->\(target)").inserted else { continue }
                    flows.append(SourceFlow(sourceId: origin, targetId: target, kind: "network"))
                }
            }
        }

        // A component sits inside the zone it names, the way a person writes
        // it by hand.
        var loose: [SourceComponent] = []
        var byZone: [String: [SourceComponent]] = [:]
        for component in components {
            if let zoneId = componentZone[component.id] {
                byZone[zoneId, default: []].append(component)
            } else {
                loose.append(component)
            }
        }

        return ArchitectureSource(
            systemName: name,
            zones: zoneOrder.compactMap { id in
                guard let zone = zones[id] else { return nil }
                return SourceZone(
                    id: zone.id,
                    kind: zone.kind,
                    network: zone.network,
                    name: zone.name,
                    components: byZone[id] ?? [],
                    source: zone.source
                )
            },
            components: loose,
            flows: flows
        )
    }

    // MARK: keeping what a person wrote

    /// What the file becomes, and what changed.
    ///
    /// An element the file marks `terraform` takes the state's technology and
    /// the state's zone; everything a person wrote on it stays. An element
    /// with no `source` is a person's own and is left whole.
    static func merge(
        _ drawn: ArchitectureSource,
        into held: ArchitectureSource?
    ) -> (source: ArchitectureSource, added: [String], removed: [String]) {
        guard let held else {
            return (drawn, drawn.everyComponent.map(\.id).sorted(), [])
        }

        var added: [String] = []
        var removed: [String] = []

        let drawnById = Dictionary(
            drawn.everyComponent.map { ($0.id, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        let heldById = Dictionary(
            held.everyComponent.map { ($0.id, $0) },
            uniquingKeysWith: { first, _ in first }
        )

        /// One component, with the state's word on what the state owns and
        /// the person's word on everything else.
        func merged(_ component: SourceComponent) -> SourceComponent {
            guard let drawnOne = drawnById[component.id],
                  component.source == sourceWord else { return component }
            return SourceComponent(
                id: component.id,
                technologyId: drawnOne.technologyId,
                name: component.name ?? drawnOne.name,
                data: component.data,
                raisesThreats: component.raisesThreats,
                runsAs: component.runsAs,
                assets: component.assets,
                holds: component.holds,
                providedBy: component.providedBy,
                source: sourceWord,
                declaredData: component.declaredData,
                shape: component.shape
            )
        }

        /// True when the state no longer holds this element and the import
        /// wrote it.
        func isGone(_ component: SourceComponent) -> Bool {
            component.source == sourceWord && drawnById[component.id] == nil
        }

        var zones: [SourceZone] = []
        for zone in held.zones {
            let kept = zone.components.filter { component in
                if isGone(component) {
                    removed.append(component.id)
                    return false
                }
                return true
            }
            let drawnZone = drawn.zones.first { $0.id == zone.id }
            // A zone the import wrote and the state no longer holds goes,
            // unless a person's own component still sits in it.
            if zone.source == sourceWord, drawnZone == nil, kept.isEmpty {
                removed.append(zone.id)
                continue
            }
            zones.append(
                SourceZone(
                    id: zone.id,
                    kind: drawnZone?.kind ?? zone.kind,
                    network: drawnZone?.network ?? zone.network,
                    name: zone.name ?? drawnZone?.name,
                    reducesRisk: zone.reducesRisk,
                    reducesRiskBy: zone.reducesRiskBy,
                    components: kept.map(merged),
                    boundary: zone.boundary,
                    description: zone.description,
                    source: zone.source
                )
            )
        }

        // A zone the state holds and the file does not.
        for zone in drawn.zones where held.zones.contains(where: { $0.id == zone.id }) == false {
            zones.append(zone)
            added.append(zone.id)
            added += zone.components.map(\.id)
        }

        var components = held.components.filter { component in
            if isGone(component) {
                removed.append(component.id)
                return false
            }
            return true
        }.map(merged)

        // A component the state holds and the file does not, put where the
        // state says it sits.
        for component in drawn.everyComponent where heldById[component.id] == nil {
            guard added.contains(component.id) == false else { continue }
            if let zoneId = drawn.zones.first(where: { zone in
                zone.components.contains { $0.id == component.id }
            })?.id {
                guard let index = zones.firstIndex(where: { $0.id == zoneId }) else { continue }
                let zone = zones[index]
                zones[index] = SourceZone(
                    id: zone.id,
                    kind: zone.kind,
                    network: zone.network,
                    name: zone.name,
                    reducesRisk: zone.reducesRisk,
                    reducesRiskBy: zone.reducesRiskBy,
                    components: zone.components + [component],
                    boundary: zone.boundary,
                    description: zone.description,
                    source: zone.source
                )
            } else {
                components.append(component)
            }
            added.append(component.id)
        }

        // A flow the state states, and every flow a person wrote. A flow of a
        // gone element goes with it.
        let goneIds = Set(removed)
        var flows = held.flows.filter { flow in
            goneIds.contains(flow.sourceId) == false && goneIds.contains(flow.targetId) == false
        }
        for flow in drawn.flows
        where flows.contains(where: { $0.sourceId == flow.sourceId && $0.targetId == flow.targetId })
            == false {
            flows.append(flow)
        }

        return (
            ArchitectureSource(
                systemName: held.systemName,
                catalogueTag: held.catalogueTag,
                technologies: held.technologies,
                zones: zones,
                components: components,
                flows: flows,
                mitigates: held.mitigates,
                riskTolerance: held.riskTolerance,
                assumptions: held.assumptions,
                useCases: held.useCases,
                exclusions: held.exclusions,
                systemAssets: held.systemAssets,
                thirdParties: held.thirdParties,
                diagrams: held.diagrams,
                requiresEvidenceAbove: held.requiresEvidenceAbove,
                owner: held.owner,
                faces: held.faces,
                threatActors: held.threatActors,
                description: held.description,
                authors: held.authors,
                links: held.links,
                repositories: held.repositories,
                created: held.created,
                reviewed: held.reviewed,
                version: held.version,
                attributes: held.attributes
            ),
            added.sorted(),
            removed.sorted()
        )
    }
}

extension ImportTerraformResponse {
    /// The lines `threatmodeller import terraform` prints for this result,
    /// against the path the file is written to, or would be written to. A
    /// caller that shows this in a window states these words rather than its
    /// own, so a person reads the same report the executable prints.
    public func importLines(path: String) -> [String] {
        switch self {
        case .imported(_, let added, let removed, let components, let zones, let flows, let unmapped):
            var lines = added.map { "added \($0)" }
            lines += removed.map { "removed \($0), which the state no longer holds" }
            lines += Self.unmappedLines(unmapped)
            lines.append(
                "imported \(components) components, \(zones) zones and \(flows) flows"
                    + " into \(path)"
            )
            return lines
        case .nothingToImport(let unmapped):
            return Self.unmappedLines(unmapped)
                + ["this state holds nothing this application draws"]
        case .unreadableState:
            return ["the state is not the JSON `terraform show -json` writes"]
        case .refused(let diagnostics):
            return diagnostics.map { $0.described(in: path) }
        }
    }

    /// One line naming every resource type this application does not map,
    /// and how many of each the state held.
    public static func unmappedLines(_ unmapped: [(type: String, count: Int)]) -> [String] {
        guard unmapped.isEmpty == false else { return [] }
        let total = unmapped.reduce(0) { $0 + $1.count }
        let named = unmapped.map { "\($0.type) (\($0.count))" }.joined(separator: ", ")
        return ["\(total) resources have no mapping: \(named)"]
    }
}

public protocol ImportTerraformIntoSystemUseCase {
    func execute(_ request: ImportTerraformIntoSystemRequest) -> ImportTerraformIntoSystemResponse
}

public struct ImportTerraformIntoSystemRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String
    /// The JSON `terraform show -json` wrote.
    public let stateText: String

    public init(root: String, systemName: String, stateText: String) {
        self.root = root
        self.systemName = systemName
        self.stateText = stateText
    }
}

public enum ImportTerraformIntoSystemResponse: Equatable, Sendable {
    /// Where the file is, and what the import did against it. `response`
    /// states `.imported` only when a file was written.
    case imported(path: String, response: ImportTerraformResponse)
    case noSuchSystem
    case notAProject(reason: String)
    case cannotWrite(reason: String)
}

/// Runs `ImportTerraform` against one system's own `.arch` file, the way
/// `threatmodeller import terraform` runs it against the file named on its
/// command line.
///
/// A window holds no path: it holds a root and a system's name, the way every
/// other project use case does. This reads the system's file, if there is
/// one, and writes the merged file back to the same place.
public struct ImportTerraformIntoSystem: ImportTerraformIntoSystemUseCase {
    private let projects: ProjectSourceGateway
    private let imports: ImportTerraformUseCase

    public init(projects: ProjectSourceGateway, sources: ArchitectureSourceGateway) {
        self.projects = projects
        self.imports = ImportTerraform(sources: sources)
    }

    public func execute(
        _ request: ImportTerraformIntoSystemRequest
    ) -> ImportTerraformIntoSystemResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch {
            return .notAProject(reason: String(describing: error))
        }
        guard let system = layout.systems.first(where: { $0.name == request.systemName }) else {
            return .noSuchSystem
        }

        let held = try? projects.read(path: system.architecturePath)
        let response = imports.execute(
            ImportTerraformRequest(
                stateText: request.stateText,
                architectureText: held,
                systemName: request.systemName
            )
        )

        if case .imported(let text, _, _, _, _, _, _) = response {
            do {
                try projects.write(text, to: system.architecturePath)
            } catch {
                return .cannotWrite(reason: String(describing: error))
            }
        }

        return .imported(path: system.architecturePath, response: response)
    }
}
