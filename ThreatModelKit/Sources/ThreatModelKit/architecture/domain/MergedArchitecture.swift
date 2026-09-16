import Foundation

/// One file of a system, as the reader hands it over.
public struct SourcePart: Equatable, Sendable {
    /// The path the text came from, as the diagnostics report it.
    public let file: String
    public let text: String

    public init(file: String, text: String) {
        self.file = file
        self.text = text
    }
}

/// Which block a file states, by kind and identity.
public enum BlockOrigin: Hashable, Sendable {
    case technology(String)
    case zone(String)
    case component(String)
    case flow(String)
    case mitigates(String)
    case assumption(String)
    case user(String)
}

/// Joins the files of one system into one source.
///
/// A system is one namespace, one diagram and one report, whichever files
/// state it. This merges what each file states, runs the checks that read two
/// files, and remembers which file each block came from so a save writes it
/// back where it was.
///
/// WARNING: the texts are never concatenated and parsed once. Every line
/// number after the first file would be wrong and every diagnostic would name
/// the wrong file.
public enum MergedArchitecture {
    /// The name a file with no `system` block reads as, until the merge takes
    /// the name from the header file.
    public static let headerlessName = ""

    public struct Merged: Equatable, Sendable {
        public let source: ArchitectureSource?
        public let diagnostics: [Diagnostic]
        /// The file each block came from.
        public let origins: [BlockOrigin: String]

        public init(
            source: ArchitectureSource?,
            diagnostics: [Diagnostic],
            origins: [BlockOrigin: String] = [:]
        ) {
            self.source = source
            self.diagnostics = diagnostics
            self.origins = origins
        }

        public var hasErrors: Bool { diagnostics.contains { $0.severity == .error } }
        public var warnings: [Diagnostic] { diagnostics.filter { $0.severity == .warning } }
    }

    /// The merge of every part, each already parsed on its own.
    ///
    /// `named` is the system's name as the directory states it, for the
    /// message that names a header whose label differs.
    public static func merge(
        _ reads: [(part: SourcePart, read: ArchitectureRead)],
        named directoryName: String? = nil
    ) -> Merged {
        var diagnostics: [Diagnostic] = []
        for one in reads {
            diagnostics += one.read.diagnostics.map { $0.in(file: one.part.file) }
        }

        let headers = reads.filter { $0.read.source?.systemName.isEmpty == false }
        guard headers.isEmpty == false else {
            let name = directoryName ?? ""
            diagnostics.append(
                fault("the system \"\(name)\" holds no file with a system block")
            )
            return Merged(source: nil, diagnostics: diagnostics)
        }
        guard headers.count == 1 else {
            let name = directoryName ?? headers[0].read.source?.systemName ?? ""
            diagnostics.append(
                fault(
                    "the system \"\(name)\" states a system block twice: "
                        + "\(headers[0].part.file) and \(headers[1].part.file)"
                )
            )
            return Merged(source: nil, diagnostics: diagnostics)
        }

        let header = headers[0]
        guard let head = header.read.source else {
            return Merged(source: nil, diagnostics: diagnostics)
        }

        // The label the header states names the system. A directory that says
        // something else is worth saying, and the label wins.
        if let directoryName, directoryName.isEmpty == false, directoryName != head.systemName {
            diagnostics.append(
                Diagnostic(
                    severity: .warning,
                    line: 1,
                    column: 1,
                    message: "the directory is \"\(directoryName)\" and the system block says "
                        + "\"\(head.systemName)\"",
                    file: header.part.file
                )
            )
        }

        var origins: [BlockOrigin: String] = [:]
        var technologies = head.technologies
        var zones = head.zones
        var components = head.components
        var flows = head.flows
        var mitigates = head.mitigates
        var assumptions = head.assumptions
        var users = head.users

        func remember(_ source: ArchitectureSource, from file: String) {
            for technology in source.technologies { origins[.technology(technology.id)] = file }
            for zone in source.zones { origins[.zone(zone.id)] = file }
            for component in source.everyComponent { origins[.component(component.id)] = file }
            for flow in source.flows { origins[.flow(flow.id)] = file }
            for edge in source.mitigates { origins[.mitigates(edge.id)] = file }
            for assumption in source.assumptions { origins[.assumption(assumption.label)] = file }
            for user in source.users { origins[.user(user.id)] = file }
        }
        remember(head, from: header.part.file)

        // Every other file states blocks and no header. A block that is
        // already declared is a fault naming both files.
        for one in reads where one.part.file != header.part.file {
            guard let part = one.read.source else { continue }
            for technology in part.technologies {
                if let held = origins[.technology(technology.id)] {
                    diagnostics.append(twice(technology.id, held, one.part.file))
                    continue
                }
                origins[.technology(technology.id)] = one.part.file
                technologies.append(technology)
            }
            for zone in part.zones {
                if let held = origins[.zone(zone.id)] {
                    diagnostics.append(twice(zone.id, held, one.part.file))
                    continue
                }
                origins[.zone(zone.id)] = one.part.file
                for component in zone.components { origins[.component(component.id)] = one.part.file }
                zones.append(zone)
            }
            for component in part.components {
                if let held = origins[.component(component.id)] {
                    diagnostics.append(
                        fault(
                            "the component \"\(component.id)\" is declared twice: "
                                + "\(held) and \(one.part.file)"
                        )
                    )
                    continue
                }
                origins[.component(component.id)] = one.part.file
                components.append(component)
            }
            for flow in part.flows {
                if let held = origins[.flow(flow.id)] {
                    diagnostics.append(
                        fault(
                            "the flow \"\(flow.id)\" is declared twice: \(held) and \(one.part.file)"
                        )
                    )
                    continue
                }
                origins[.flow(flow.id)] = one.part.file
                flows.append(flow)
            }
            for edge in part.mitigates {
                if let held = origins[.mitigates(edge.id)] {
                    diagnostics.append(
                        fault(
                            "the mitigates edge \"\(edge.id)\" is declared twice: "
                                + "\(held) and \(one.part.file)"
                        )
                    )
                    continue
                }
                origins[.mitigates(edge.id)] = one.part.file
                mitigates.append(edge)
            }
            for assumption in part.assumptions {
                if let held = origins[.assumption(assumption.label)] {
                    diagnostics.append(
                        fault(
                            "the assumption \"\(assumption.label)\" is declared twice: "
                                + "\(held) and \(one.part.file)"
                        )
                    )
                    continue
                }
                origins[.assumption(assumption.label)] = one.part.file
                assumptions.append(assumption)
            }
            for user in part.users {
                if let held = origins[.user(user.id)] {
                    diagnostics.append(
                        fault(
                            "the user \"\(user.id)\" is declared twice: \(held) and \(one.part.file)"
                        )
                    )
                    continue
                }
                origins[.user(user.id)] = one.part.file
                users.append(user)
            }
        }

        // A user and a component share one namespace, whichever files
        // declare them.
        for user in users {
            guard let held = origins[.component(user.id)], let own = origins[.user(user.id)] else {
                continue
            }
            diagnostics.append(
                fault("\"\(user.id)\" is declared as a component and as a user: \(held) and \(own)")
            )
        }

        let joined = ArchitectureSource(
            systemName: head.systemName,
            catalogueTag: head.catalogueTag,
            technologies: technologies,
            zones: zones,
            components: components,
            flows: flows,
            mitigates: mitigates,
            riskTolerance: head.riskTolerance,
            assumptions: assumptions,
            requiresEvidenceAbove: head.requiresEvidenceAbove,
            owner: head.owner,
            faces: head.faces,
            threatActors: head.threatActors,
            users: users
        )

        // Every file is read now, so a component that states a zone finds it
        // whichever file declares it.
        let placement = placed(joined)
        let merged = placement.source
        for (componentId, zoneId) in placement.unknownZones {
            diagnostics.append(
                fault(
                    "the component \"\(componentId)\" states zone \"\(zoneId)\", which this "
                        + "system does not declare"
                )
            )
        }
        for zone in merged.zones where zone.components.isEmpty {
            diagnostics.append(
                Diagnostic(
                    severity: .warning,
                    line: 1,
                    column: 1,
                    message: "the zone \"\(zone.id)\" holds no components",
                    file: origins[.zone(zone.id)]
                )
            )
        }

        // The checks that read two identifiers run here, over every file.
        let componentIds = Set(merged.everyComponent.map(\.id))
        for user in merged.users {
            for reached in user.reaches where componentIds.contains(reached) == false {
                diagnostics.append(
                    fault(
                        "the user \"\(user.id)\" reaches \"\(reached)\", which this system does "
                            + "not declare"
                    )
                )
            }
        }
        let declared = Set(merged.everyNodeId)
        for flow in merged.flows {
            if declared.contains(flow.sourceId) == false {
                diagnostics.append(
                    fault(
                        "the flow starts at \"\(flow.sourceId)\", which this system does not declare"
                    )
                )
            }
            if declared.contains(flow.targetId) == false {
                diagnostics.append(
                    fault(
                        "the flow ends at \"\(flow.targetId)\", which this system does not declare"
                    )
                )
            }
        }
        for edge in merged.mitigates {
            if declared.contains(edge.sourceId) == false {
                diagnostics.append(
                    fault(
                        "the mitigates edge starts at \"\(edge.sourceId)\", which this system does "
                            + "not declare"
                    )
                )
            }
            if declared.contains(edge.targetId) == false {
                diagnostics.append(
                    fault(
                        "the mitigates edge ends at \"\(edge.targetId)\", which this system does "
                            + "not declare"
                    )
                )
            }
        }

        let refused = diagnostics.contains { $0.severity == .error }
        return Merged(
            source: refused ? nil : merged,
            diagnostics: diagnostics,
            origins: origins
        )
    }

    /// The source with every top-level component that states a zone moved
    /// into that zone, and the pairs that name a zone the source does not
    /// declare, in file order.
    ///
    /// A reader downstream reads membership from the nesting alone, so the
    /// attribute is a way to write a file and not a second way to hold a
    /// model. A component that states a zone nothing declares stays at the
    /// top level; the caller refuses the source.
    public static func placed(
        _ source: ArchitectureSource
    ) -> (source: ArchitectureSource, unknownZones: [(componentId: String, zoneId: String)]) {
        var loose: [SourceComponent] = []
        var joining: [String: [SourceComponent]] = [:]
        var unknown: [(componentId: String, zoneId: String)] = []
        let zoneIds = Set(source.zones.map(\.id))
        for component in source.components {
            guard let zoneId = component.zoneId else {
                loose.append(component)
                continue
            }
            guard zoneIds.contains(zoneId) else {
                unknown.append((componentId: component.id, zoneId: zoneId))
                loose.append(component)
                continue
            }
            joining[zoneId, default: []].append(component)
        }
        guard joining.isEmpty == false else { return (source, unknown) }

        let zones = source.zones.map { zone in
            zone.holding(zone.components + (joining[zone.id] ?? []))
        }
        return (
            ArchitectureSource(
                systemName: source.systemName,
                catalogueTag: source.catalogueTag,
                technologies: source.technologies,
                zones: zones,
                components: loose,
                flows: source.flows,
                mitigates: source.mitigates,
                riskTolerance: source.riskTolerance,
                assumptions: source.assumptions,
                useCases: source.useCases,
                exclusions: source.exclusions,
                systemAssets: source.systemAssets,
                thirdParties: source.thirdParties,
                diagrams: source.diagrams,
                requiresEvidenceAbove: source.requiresEvidenceAbove,
                owner: source.owner,
                faces: source.faces,
                threatActors: source.threatActors,
                description: source.description,
                authors: source.authors,
                links: source.links,
                repositories: source.repositories,
                created: source.created,
                reviewed: source.reviewed,
                version: source.version,
                attributes: source.attributes,
                users: source.users
            ),
            unknown
        )
    }

    /// Which file each block of one source came from, for the one-file case.
    public static func origins(
        of source: ArchitectureSource?,
        in file: String
    ) -> [BlockOrigin: String] {
        guard let source else { return [:] }
        var origins: [BlockOrigin: String] = [:]
        for technology in source.technologies { origins[.technology(technology.id)] = file }
        for zone in source.zones { origins[.zone(zone.id)] = file }
        for component in source.everyComponent { origins[.component(component.id)] = file }
        for flow in source.flows { origins[.flow(flow.id)] = file }
        for edge in source.mitigates { origins[.mitigates(edge.id)] = file }
        for assumption in source.assumptions { origins[.assumption(assumption.label)] = file }
        for user in source.users { origins[.user(user.id)] = file }
        return origins
    }

    private static func twice(_ id: String, _ first: String, _ second: String) -> Diagnostic {
        fault("\"\(id)\" is declared twice: \(first) and \(second)")
    }

    private static func fault(_ message: String) -> Diagnostic {
        Diagnostic(severity: .error, line: 1, column: 1, message: message)
    }
}
