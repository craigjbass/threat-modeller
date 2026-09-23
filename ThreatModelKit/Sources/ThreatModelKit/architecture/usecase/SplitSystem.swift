import Foundation

public protocol SplitSystemUseCase {
    func execute(_ request: SplitSystemRequest) -> SplitSystemResponse
}

public struct SplitSystemRequest: Equatable, Sendable {
    public let root: String
    public let systemName: String

    public init(root: String, systemName: String) {
        self.root = root
        self.systemName = systemName
    }
}

public enum SplitSystemResponse: Equatable, Sendable {
    case split
    case noSuchSystem
    /// The system the files state cannot be divided: the merge refuses it, or
    /// two zones write one file name.
    case refused(reason: String)
    case cannotWrite(reason: String)
}

/// Divides one system into the directory form, one architecture file per
/// zone.
///
/// The header file takes the `system` block, every header field, the
/// technologies, the users, the assumptions and every component outside a
/// zone. Each zone takes a file of its own, holding the zone block, the
/// components it holds, and every flow and mitigates edge whose source sits
/// in that zone. The answers follow their element: an element declared in
/// `arch/edge.arch` is answered in `controls/edge.controls`. Each attack tree
/// takes a file of its own.
///
/// The split reads the system and writes files, so a file that was not in the
/// writer's order changes shape. A system already in this form is read and
/// written the same way, which sorts a subproject a person wrote by hand.
public struct SplitSystem: SplitSystemUseCase {
    private let projects: ProjectSourceGateway
    private let sources: ArchitectureSourceGateway
    private let controlsSources: ControlsSourceGateway
    private let attackTreeSources: AttackTreeSourceGateway

    public init(
        projects: ProjectSourceGateway,
        sources: ArchitectureSourceGateway,
        controlsSources: ControlsSourceGateway,
        attackTreeSources: AttackTreeSourceGateway
    ) {
        self.projects = projects
        self.sources = sources
        self.controlsSources = controlsSources
        self.attackTreeSources = attackTreeSources
    }

    public func execute(_ request: SplitSystemRequest) -> SplitSystemResponse {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: request.root)
        } catch {
            return .cannotWrite(reason: String(describing: error))
        }
        guard let system = layout.system(named: request.systemName) else {
            return .noSuchSystem
        }

        var parts: [SourcePart] = []
        for path in system.architecturePaths where projects.exists(path: path) {
            guard let text = try? projects.read(path: path) else {
                return .cannotWrite(reason: "the file \"\(path)\" could not be read")
            }
            parts.append(SourcePart(file: path, text: text))
        }
        let merged = sources.read(parts, named: system.isSplit ? system.name : nil)
        guard let source = merged.source else {
            let first = merged.diagnostics.first { $0.severity == .error }?.message ?? "unknown"
            return .refused(
                reason: "the system \"\(request.systemName)\" cannot be split: \(first)"
            )
        }

        let places: Places
        switch Places.of(source, in: layout, named: request.systemName) {
        case .refused(let reason): return .refused(reason: reason)
        case .placed(let made): places = made
        }

        let written = ArchitectureSourceSplit.parts(
            of: source,
            origins: places.origins,
            headerFile: places.headerFile,
            sources: sources
        )

        if let failure = writeArchitecture(written, of: system) { return .cannotWrite(reason: failure) }
        if let failure = writeAnswers(of: system, places: places) { return .cannotWrite(reason: failure) }
        if let failure = writeTrees(of: system, places: places) { return .cannotWrite(reason: failure) }
        if let failure = moveGovernance(of: system, places: places) { return .cannotWrite(reason: failure) }

        try? projects.delete(path: system.reportPath)
        return .split
    }

    // MARK: the files each block goes to

    /// The file each block of one system goes to, and the directories the
    /// files sit in.
    struct Places {
        let subproject: String
        let headerFile: String
        let origins: [BlockOrigin: String]
        /// The architecture file each element identifier is declared in, for
        /// the answers that name that element.
        let fileOfElement: [String: String]

        enum Made {
            case placed(Places)
            case refused(reason: String)
        }

        static func of(
            _ source: ArchitectureSource,
            in layout: ProjectLayout,
            named systemName: String
        ) -> Made {
            let subproject = ProjectConvention.path(layout.directory, systemName)
            let architecture = ProjectConvention.path(
                subproject,
                ProjectConvention.kindDirectory(ProjectConvention.architectureExtension)
            )
            let headerStem = ProjectConvention.stem(forSystemNamed: systemName)
            let headerFile = ProjectConvention.path(
                architecture,
                "\(headerStem).\(ProjectConvention.architectureExtension)"
            )

            var origins: [BlockOrigin: String] = [:]
            var fileOfElement: [String: String] = [:]
            var zoneOfFile: [String: String] = [:]

            for zone in source.zones {
                let stem = ProjectConvention.stem(forSystemNamed: zone.id)
                let file = stem == headerStem
                    ? headerFile
                    : ProjectConvention.path(
                        architecture,
                        "\(stem).\(ProjectConvention.architectureExtension)"
                    )
                if file != headerFile, let other = zoneOfFile[file] {
                    return .refused(
                        reason: "the zone \"\(other)\" and the zone \"\(zone.id)\" both write "
                            + "the file \"\(stem).\(ProjectConvention.architectureExtension)\""
                    )
                }
                zoneOfFile[file] = zone.id
                origins[.zone(zone.id)] = file
                fileOfElement[zone.id] = file
                for component in zone.components {
                    origins[.component(component.id)] = file
                    fileOfElement[component.id] = file
                }
            }

            for component in source.components {
                origins[.component(component.id)] = headerFile
                fileOfElement[component.id] = headerFile
            }
            for technology in source.technologies { origins[.technology(technology.id)] = headerFile }
            for assumption in source.assumptions { origins[.assumption(assumption.label)] = headerFile }
            for user in source.users {
                origins[.user(user.id)] = headerFile
                fileOfElement[user.id] = headerFile
            }
            // A flow and a mitigates edge sit in the file its source sits in.
            for flow in source.flows {
                let file = fileOfElement[flow.sourceId] ?? headerFile
                origins[.flow(flow.id)] = file
                fileOfElement[flow.id] = file
            }
            for edge in source.mitigates {
                origins[.mitigates(edge.id)] = fileOfElement[edge.sourceId] ?? headerFile
            }

            return .placed(
                Places(
                    subproject: subproject,
                    headerFile: headerFile,
                    origins: origins,
                    fileOfElement: fileOfElement
                )
            )
        }

        /// The controls file that mirrors an architecture file, and the
        /// header's controls file for an answer about the system itself.
        func controlsFile(mirroring architectureFile: String) -> String {
            let stem = architectureFile.isEmpty
                ? ProjectSystem.stem(of: headerFile)
                : ProjectSystem.stem(of: architectureFile)
            return ProjectConvention.path(
                ProjectConvention.path(
                    subproject,
                    ProjectConvention.kindDirectory(ProjectConvention.controlsExtension)
                ),
                "\(stem).\(ProjectConvention.controlsExtension)"
            )
        }

        func treeFile(of treeId: String) -> String {
            ProjectConvention.path(
                ProjectConvention.path(
                    subproject,
                    ProjectConvention.kindDirectory(ProjectConvention.attackTreeExtension)
                ),
                "\(ProjectConvention.stem(forSystemNamed: treeId))"
                    + ".\(ProjectConvention.attackTreeExtension)"
            )
        }

        var governanceFile: String {
            ProjectConvention.path(
                subproject,
                "\(ProjectSystem.stem(of: headerFile)).\(ProjectConvention.governanceExtension)"
            )
        }
    }

    // MARK: writing

    /// Writes each text and deletes every file of that kind the system held
    /// and the split did not write. Answers the failure's reason, or nil.
    private func replace(_ texts: [String: String], held: [String]) -> String? {
        for (path, text) in texts.sorted(by: { $0.key < $1.key }) {
            do {
                try projects.write(text, to: path)
            } catch {
                return String(describing: error)
            }
        }
        for path in held where texts[path] == nil {
            try? projects.delete(path: path)
        }
        return nil
    }

    private func writeArchitecture(_ written: [SourcePart], of system: ProjectSystem) -> String? {
        var texts: [String: String] = [:]
        for part in written { texts[part.file] = part.text }
        return replace(texts, held: system.architecturePaths)
    }

    private func writeAnswers(of system: ProjectSystem, places: Places) -> String? {
        var held: [String: String] = [:]
        for path in system.controlsPaths where projects.exists(path: path) {
            guard let text = try? projects.read(path: path) else { continue }
            held[path] = text
        }
        guard held.isEmpty == false else { return nil }
        guard let joined = ControlsSourceMerge.text(of: held, sources: controlsSources),
              let answers = controlsSources.read(joined).source else {
            return nil
        }

        let texts = ControlsSourceMerge.split(
            answers,
            sources: controlsSources,
            held: [:],
            originOf: { places.fileOfElement[$0.sourceId] },
            controlsPathOf: { places.controlsFile(mirroring: $0) }
        )
        return replace(texts, held: system.controlsPaths)
    }

    private func writeTrees(of system: ProjectSystem, places: Places) -> String? {
        var trees: [SourceAttackTree] = []
        var systemName: String?
        var catalogueTag: String?
        for path in system.attackTreePaths where projects.exists(path: path) {
            guard let text = try? projects.read(path: path),
                  let source = attackTreeSources.read(text).source else { continue }
            systemName = systemName ?? source.systemName
            catalogueTag = catalogueTag ?? source.catalogueTag
            trees += source.trees
        }
        guard let systemName, trees.isEmpty == false else { return nil }

        var texts: [String: String] = [:]
        for tree in trees {
            let path = places.treeFile(of: tree.id)
            texts[path] = attackTreeSources.write(
                AttackTreeSource(systemName: systemName, catalogueTag: catalogueTag, trees: [tree])
            )
        }
        return replace(texts, held: system.attackTreePaths)
    }

    private func moveGovernance(of system: ProjectSystem, places: Places) -> String? {
        let from = system.governancePath
        let into = places.governanceFile
        guard from != into, projects.exists(path: from) else { return nil }
        do {
            try projects.write(try projects.read(path: from), to: into)
            try projects.delete(path: from)
        } catch {
            return String(describing: error)
        }
        return nil
    }
}
