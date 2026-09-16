import ArchitectureDSL
import CatalogueGateways
import DiagramRendering
import FileGateways
import Foundation
import ThreatModelKit

/// The verbs, and what each one returns to a shell.
///
/// The executable is a few lines over this, so a test calls a verb in process
/// and asserts the exit code and the printed text. No test shells out.
public struct CommandLineApplication {
    public enum ExitCode: Int32 {
        case success = 0
        case unanswered = 1
        case didNotParse = 2
        case fileFault = 3
        /// `git` failed, is absent, or the clone timed out. The message
        /// carries `git`'s own output.
        case fetchFailed = 4
    }

    private let projects: ProjectSourceGateway
    private let architecture: ArchitectureSourceGateway
    private let controls: ControlsSourceGateway
    private let attackTrees: AttackTreeSourceGateway
    private let libraries: LibrarySourceGateway
    private let history: GitHistoryGateway
    private let fetcher: LibraryFetching
    /// Where the ATT&CK data sits on this machine, and what fetches it.
    private let attackData: AttackDataGateway
    private let downloader: AttackDownloading
    /// The groups on this machine, read the first time a verb asks.
    private let mitreActors: MitreActorSource
    /// Built once a catalogue is known, which is only when a verb needs one.
    private let makeCatalogue: () throws -> TechnologyCatalogue
    /// What arrives on standard input. `import` reads a Terraform state from
    /// it, and a test hands one over without a pipe.
    private let standardInput: () -> String

    public init(
        projects: ProjectSourceGateway,
        architecture: ArchitectureSourceGateway = HclArchitectureSource(),
        controls: ControlsSourceGateway = HclControlsSource(),
        attackTrees: AttackTreeSourceGateway = HclAttackTreeSource(),
        libraries: LibrarySourceGateway = HclLibrarySource(),
        history: GitHistoryGateway = GitHistory(),
        fetcher: LibraryFetching = GitLibraryFetcher(),
        attackData: AttackDataGateway = FileSystemAttackData(),
        downloader: AttackDownloading = CurlDownloader(),
        catalogue: @escaping () throws -> TechnologyCatalogue = { try BundledTechnologyCatalogue() },
        standardInput: @escaping () -> String = CommandLineApplication.everyLineOfStandardInput
    ) {
        self.standardInput = standardInput
        self.attackData = attackData
        self.downloader = downloader
        mitreActors = MitreActorSource(data: attackData)
        self.projects = projects
        self.architecture = architecture
        self.controls = controls
        self.attackTrees = attackTrees
        self.libraries = libraries
        self.history = history
        self.fetcher = fetcher
        makeCatalogue = catalogue
    }

    /// `arguments` is `CommandLine.arguments`, so the first one is the
    /// executable's own path.
    public func run(arguments: [String], output: (String) -> Void) -> Int32 {
        var words = Array(arguments.dropFirst())
        var isQuiet = false
        var isForced = false
        var catalogueDirectory: String?
        var tolerance: String?
        var pictures: Set<DiagramFormat> = []
        var wantsHtml = false
        var machineOutput = MachineOutput.plain
        var unknownFormat: String?
        var formatWord: String?
        var wantsStandardOutput = false
        var diagramLanguage: String?
        var templatePath: String?
        var fieldWords: String?
        var sortWord: String?
        var wantsHeader = true
        var allowsWrites = false
        var wantsJson = false
        var commits = ReadRiskHistory.defaultCommits

        var flagless: [String] = []
        var index = 0
        while index < words.count {
            switch words[index] {
            case "--quiet", "-q":
                isQuiet = true
            case "--force", "-f":
                isForced = true
            case "--catalogue":
                index += 1
                catalogueDirectory = index < words.count ? words[index] : nil
            case "--tolerance":
                index += 1
                tolerance = index < words.count ? words[index] : nil
            case "--commits":
                index += 1
                commits = index < words.count ? (Int(words[index]) ?? commits) : commits
            case "--format":
                index += 1
                let named = index < words.count ? words[index] : ""
                formatWord = named
                if let format = MachineOutput.named(named) {
                    machineOutput = format
                } else {
                    unknownFormat = named
                }
            case "--svg":
                pictures.insert(.svg)
            case "--png":
                pictures.insert(.png)
            case "--mermaid":
                pictures.insert(.mermaid)
            case "--dot":
                pictures.insert(.dot)
            case "--d2":
                pictures.insert(.d2)
            case "--template":
                index += 1
                templatePath = index < words.count ? words[index] : nil
            case "--diagram":
                index += 1
                diagramLanguage = index < words.count ? words[index] : nil
            case "--html":
                wantsHtml = true
            case "--stdout":
                wantsStandardOutput = true
            case "--fields":
                index += 1
                fieldWords = index < words.count ? words[index] : nil
            case "--sort":
                index += 1
                sortWord = index < words.count ? words[index] : nil
            case "--allow-writes":
                allowsWrites = true
            case "--no-header":
                wantsHeader = false
            case "--json":
                wantsJson = true
            case "-o":
                index += 1
                if index < words.count { flagless.append("-o:" + words[index]) }
            default:
                flagless.append(words[index])
            }
            index += 1
        }
        words = flagless

        // `export` reads `--format` as the shape it writes, not as the shape a
        // diagnostic takes, so a word this list does not hold is its own
        // fault to report.
        if words.first == "export" { unknownFormat = nil }

        if let unknownFormat {
            output(
                "threatmodeller: there is no format \"\(unknownFormat)\";"
                    + " this application holds \(MachineOutput.names)"
            )
            return ExitCode.didNotParse.rawValue
        }

        guard let verb = words.first else {
            output(Self.usage)
            return ExitCode.didNotParse.rawValue
        }

        // The catalogue directory is read by the gateways through this, so a
        // Linux binary can be told where its data is.
        if let catalogueDirectory {
            CatalogueLocation.directory = catalogueDirectory
        }

        let root = words.dropFirst().first { $0.hasPrefix("-o:") == false } ?? "."

        switch verb {
        case "format":
            return format(root: root, isQuiet: isQuiet, as: machineOutput, output: output)
        case "compile":
            return compile(root: root, isQuiet: isQuiet, as: machineOutput, output: output)
        case "check":
            return check(root: root, tolerance: tolerance, as: machineOutput, output: output)
        case "history":
            return self.history(root: root, commits: commits, as: machineOutput, output: output)
        case "library":
            return library(words: Array(words.dropFirst()), isForced: isForced, output: output)
        case "split":
            return split(words: Array(words.dropFirst()), output: output)
        case "attack":
            return attack(words: Array(words.dropFirst()), output: output)
        case "actors":
            return actors(words: Array(words.dropFirst()), output: output)
        case "report":
            let into = words.first { $0.hasPrefix("-o:") }.map { String($0.dropFirst(3)) }
            return report(
                root: root,
                into: into,
                templatePath: templatePath,
                diagramLanguage: diagramLanguage,
                wantsHtml: wantsHtml,
                isQuiet: isQuiet,
                commits: commits,
                output: output
            )
        case "draw":
            let into = words.first { $0.hasPrefix("-o:") }.map { String($0.dropFirst(3)) }
            return draw(root: root, into: into, wants: pictures, isQuiet: isQuiet, output: output)
        case "lsp":
            return serveLsp()
        case "mcp":
            return serveMcp(root: root, allowsWrites: allowsWrites, output: output)
        case "import":
            return importing(words: Array(words.dropFirst()), isQuiet: isQuiet, output: output)
        case "list":
            return list(
                root: root,
                fields: fieldWords,
                sort: sortWord,
                wantsHeader: wantsHeader,
                wantsJson: wantsJson,
                output: output
            )
        case "export":
            let into = words.first { $0.hasPrefix("-o:") }.map { String($0.dropFirst(3)) }
            return export(
                root: root,
                into: into,
                format: formatWord ?? ExportFormat.json.rawValue,
                wantsStandardOutput: wantsStandardOutput,
                isQuiet: isQuiet,
                output: output
            )
        case "help", "--help", "-h":
            output(Self.usage)
            return ExitCode.success.rawValue
        default:
            output("threatmodeller: there is no verb \"\(verb)\"")
            output(Self.usage)
            return ExitCode.didNotParse.rawValue
        }
    }

    /// Rewrites every architecture file in the canonical shape.
    /// One diagnostic, in the shape the format asks for.
    ///
    /// `json` is a whole-run format and `compile` and `format` write a line at
    /// a time, so both write the plain line under it.
    static func said(
        _ diagnostic: Diagnostic,
        in file: String,
        as machineOutput: MachineOutput
    ) -> String {
        machineOutput == .github
            ? GitHubOutput.line(diagnostic, in: file)
            : diagnostic.described(in: file)
    }

    private func format(
        root: String,
        isQuiet: Bool,
        as machineOutput: MachineOutput,
        output: (String) -> Void
    ) -> Int32 {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: root)
        } catch {
            output("threatmodeller: \(Self.described(error))")
            return ExitCode.fileFault.rawValue
        }

        if layout.systems.isEmpty && layout.libraryPaths.isEmpty {
            output("threatmodeller: \(layout.directory) holds no .arch files")
            return ExitCode.success.rawValue
        }

        var code = ExitCode.success

        // The libraries a project vendors are the project's files too, so
        // `format` writes them in the canonical shape the way it writes an
        // architecture file.
        for path in layout.libraryPaths {
            if formatLibrary(at: path, isQuiet: isQuiet, output: output) == false {
                code = .didNotParse
            }
        }
        for system in layout.systems {
            // A split system's part files are rewritten too. The header file
            // is the one the loop below writes.
            for path in system.architecturePaths where path != system.headerPath {
                if formatPart(at: path, isQuiet: isQuiet, output: output) == false {
                    code = .didNotParse
                }
            }

            let text: String
            do {
                text = try projects.read(path: system.architecturePath)
            } catch {
                output("threatmodeller: \(Self.described(error))")
                code = .fileFault
                continue
            }

            let read = architecture.read(text)
            guard let source = read.source, read.hasErrors == false else {
                for diagnostic in read.diagnostics {
                    output(diagnostic.described(in: system.architecturePath))
                }
                code = .didNotParse
                continue
            }
            for diagnostic in read.warnings {
                output(diagnostic.described(in: system.architecturePath))
            }

            let written = architecture.write(source)
            if written != text {
                do {
                    try projects.write(written, to: system.architecturePath)
                    if isQuiet == false { output("formatted \(system.architecturePath)") }
                } catch {
                    output("threatmodeller: \(Self.described(error))")
                    code = .fileFault
                }
            } else if isQuiet == false {
                output("unchanged \(system.architecturePath)")
            }

            if formatAttackTree(of: system, isQuiet: isQuiet, output: output) == false {
                code = .fileFault
            }
        }
        return code.rawValue
    }

    /// Rewrites one `.lib` file in the canonical shape.
    ///
    /// False means the file did not parse or could not be written. A file that
    /// does not parse is left as it is and its diagnostics are printed, the
    /// way an architecture file is.
    private func formatLibrary(
        at path: String,
        isQuiet: Bool,
        output: (String) -> Void
    ) -> Bool {
        let text: String
        do {
            text = try projects.read(path: path)
        } catch {
            output("threatmodeller: \(Self.described(error))")
            return false
        }

        let read = libraries.read(text)
        guard let source = read.source, read.hasErrors == false else {
            for diagnostic in read.diagnostics { output(diagnostic.described(in: path)) }
            return false
        }
        for diagnostic in read.warnings { output(diagnostic.described(in: path)) }

        let written = libraries.write(source)
        guard written != text else {
            if isQuiet == false { output("unchanged \(path)") }
            return true
        }

        do {
            try projects.write(written, to: path)
            if isQuiet == false { output("formatted \(path)") }
            return true
        } catch {
            output("threatmodeller: \(Self.described(error))")
            return false
        }
    }

    /// Rewrites one part file of a split system in the canonical shape.
    ///
    /// A part holds no `system` block, so it is read as a part and written
    /// back with its blocks in the order it stated them.
    private func formatPart(at path: String, isQuiet: Bool, output: (String) -> Void) -> Bool {
        guard let text = try? projects.read(path: path) else { return false }

        let read = architecture.readPart(text)
        guard let source = read.source, read.hasErrors == false else {
            for diagnostic in read.diagnostics { output(diagnostic.described(in: path)) }
            return false
        }
        for diagnostic in read.warnings { output(diagnostic.described(in: path)) }

        let written = architecture.writePart(source)
        guard written != text else {
            if isQuiet == false { output("unchanged \(path)") }
            return true
        }
        do {
            try projects.write(written, to: path)
            if isQuiet == false { output("formatted \(path)") }
            return true
        } catch {
            output("threatmodeller: \(Self.described(error))")
            return false
        }
    }

    // MARK: split

    /// `threatmodeller split <system> [<root>]` turns one flat system into the
    /// directory form.
    ///
    /// It moves files and writes no new content, so a person reads the diff
    /// and sees moves.
    private func split(words: [String], output: (String) -> Void) -> Int32 {
        let rest = words.filter { $0.hasPrefix("-") == false }
        guard let name = rest.first else {
            output("threatmodeller: split takes a system name")
            return ExitCode.didNotParse.rawValue
        }
        let root = rest.count > 1 ? rest[1] : "."

        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: root)
        } catch {
            output("threatmodeller: \(Self.described(error))")
            return ExitCode.fileFault.rawValue
        }

        guard let system = layout.system(named: name) else {
            output("threatmodeller: this project holds no system called \"\(name)\"")
            return ExitCode.fileFault.rawValue
        }
        guard system.isSplit == false else {
            output("threatmodeller: the system \"\(name)\" is already a directory")
            return ExitCode.fileFault.rawValue
        }

        let subproject = ProjectConvention.path(layout.directory, name)
        func move(_ from: String, _ fileExtension: String) -> Bool {
            guard projects.exists(path: from) else { return true }
            let stem = ((from as NSString).lastPathComponent)
            let into = ProjectConvention.path(
                ProjectConvention.path(subproject, ProjectConvention.kindDirectory(fileExtension)),
                stem
            )
            do {
                try projects.write(try projects.read(path: from), to: into)
                try projects.delete(path: from)
                output("moved \(from) to \(into)")
                return true
            } catch {
                output("threatmodeller: \(Self.described(error))")
                return false
            }
        }

        guard move(system.architecturePath, ProjectConvention.architectureExtension),
              move(system.controlsPath, ProjectConvention.controlsExtension),
              move(system.attackTreePath, ProjectConvention.attackTreeExtension) else {
            return ExitCode.fileFault.rawValue
        }

        // The report is written, not read, and the next `report` writes it
        // inside the subproject.
        try? projects.delete(path: system.reportPath)
        return ExitCode.success.rawValue
    }

    // MARK: attack

    /// `threatmodeller attack sync [<tag>]` and `threatmodeller attack verify`.
    ///
    /// The words after the verb are the tag and the root, in either order: a
    /// tag reads as a version and everything else is the root.
    private func attack(words: [String], output: (String) -> Void) -> Int32 {
        let verb = words.first ?? ""
        let rest = words.dropFirst().filter { $0.hasPrefix("-") == false }
        let root = rest.first { TagVersion($0) == nil } ?? "."
        switch verb {
        case "sync":
            // A tag reads `v19.2` or `19.2`; anything else in the words is the
            // root, which the caller has already read.
            let tag = rest.first { TagVersion($0) != nil }
            let wanted = tag ?? AttackRelease.default
            // A person typed the verb, so it says what it will do and does it.
            output(
                "threatmodeller: downloading ATT&CK \(wanted) from "
                    + "\(AttackRelease.address(of: wanted)), about "
                    + "\(AttackRelease.bundleBytes / 1_000_000) MB"
            )
            let response = SynchroniseAttack(
                projects: projects,
                data: attackData,
                downloader: downloader
            ).execute(SynchroniseAttackRequest(root: root, tag: tag))

            switch response {
            case .synchronised(let tag, let groups, let techniques):
                output("threatmodeller: ATT&CK \(tag): \(groups) groups, \(techniques) techniques")
                output("threatmodeller: written to \(attackData.directory)")
                return ExitCode.success.rawValue
            case .notAProject(let reason):
                output("threatmodeller: \(reason)")
                return ExitCode.fileFault.rawValue
            case .cannotDownload(let reason), .cannotExtract(let reason), .cannotWrite(let reason):
                output("threatmodeller: \(reason)")
                return ExitCode.fileFault.rawValue
            }
        case "verify":
            switch VerifyAttack(projects: projects, data: attackData)
                .execute(VerifyAttackRequest(root: root)) {
            case .matches(let tag):
                output("threatmodeller: ATT&CK \(tag) matches \(AttackLock.fileName)")
                return ExitCode.success.rawValue
            case .noLockFile:
                output(
                    "threatmodeller: this project states no ATT&CK release; "
                        + "run threatmodeller attack sync"
                )
                return ExitCode.success.rawValue
            case .notSynchronised(let tag):
                output(
                    "threatmodeller: this machine holds no ATT&CK data; "
                        + "run threatmodeller attack sync \(tag)"
                )
                return ExitCode.unanswered.rawValue
            case .doesNotMatch(let tag, let fileName):
                output(
                    "threatmodeller: \(fileName) is not the file ATT&CK \(tag) states; "
                        + "run threatmodeller attack sync \(tag)"
                )
                return ExitCode.unanswered.rawValue
            case .notAProject(let reason):
                output("threatmodeller: \(reason)")
                return ExitCode.fileFault.rawValue
            }
        default:
            output("threatmodeller: attack holds sync and verify, not \"\(verb)\"")
            return ExitCode.didNotParse.rawValue
        }
    }

    // MARK: actors

    /// `threatmodeller actors list [--mitre] [<root>]`.
    private func actors(words: [String], output: (String) -> Void) -> Int32 {
        let verb = words.first ?? ""
        guard verb == "list" else {
            output("threatmodeller: actors holds list, not \"\(verb)\"")
            return ExitCode.didNotParse.rawValue
        }

        let catalogue: TechnologyCatalogue
        do {
            catalogue = try makeCatalogue()
        } catch {
            output("threatmodeller: \(Self.described(error))")
            return ExitCode.fileFault.rawValue
        }

        let listed = ListThreatActorsInUse(catalogue: catalogue, mitre: mitreActors)
            .execute(
                ListThreatActorsInUseRequest(mitreOnly: words.contains("--mitre"))
            )

        guard listed.actors.isEmpty == false else {
            output(
                "threatmodeller: this machine holds no ATT&CK data; "
                    + "run threatmodeller attack sync"
            )
            return ExitCode.success.rawValue
        }

        for actor in listed.actors {
            output(
                "\(actor.id)  \(actor.name)  \(actor.capabilityLabel)  "
                    + "\(actor.threatsPerformed) threats"
            )
        }
        return ExitCode.success.rawValue
    }

    /// Every architecture file of a system, read.
    static func parts(of system: ProjectSystem, projects: ProjectSourceGateway) -> [SourcePart] {
        system.architecturePaths.compactMap { path in
            (try? projects.read(path: path)).map { SourcePart(file: path, text: $0) }
        }
    }

    /// Every controls file of a system, by path.
    static func controlsTexts(
        of system: ProjectSystem,
        projects: ProjectSourceGateway
    ) -> [String: String] {
        var held: [String: String] = [:]
        for path in system.controlsPaths where projects.exists(path: path) {
            held[path] = (try? projects.read(path: path)) ?? ""
        }
        return held
    }

    /// Every attack tree file of a system, read.
    static func treeTexts(of system: ProjectSystem, projects: ProjectSourceGateway) -> [String] {
        system.attackTreePaths
            .filter { projects.exists(path: $0) }
            .compactMap { try? projects.read(path: $0) }
    }

    /// The compiled answers, split into one text per controls file.
    ///
    /// An answer goes to the file that mirrors the architecture file the
    /// element it answers came from.
    static func routedControls(
        _ compiled: String,
        of system: ProjectSystem,
        parts: [SourcePart],
        held: [String: String],
        useCases: CommandLineDependencies
    ) -> [String: String] {
        let sources = useCases.controlsSources
        guard let source = sources.read(compiled).source else { return [:] }

        let merged = useCases.architectureSources.read(parts, named: system.name)
        let origins = merged.origins

        return ControlsSourceMerge.split(
            source,
            sources: sources,
            held: held,
            originOf: { answer in
                switch answer.sourceKind {
                case "component": origins[.component(answer.sourceId)]
                case "zone": origins[.zone(answer.sourceId)]
                case "flow", "connection": origins[.flow(answer.sourceId)]
                default: nil
                }
            },
            // An answer whose element no file states — a threat on the system
            // itself — goes with the header file.
            controlsPathOf: { $0.isEmpty ? system.controlsPath : system.controlsPath(mirroring: $0) }
        )
    }

    /// The trees beside a system, or nil when the project holds no such file.
    private func treeText(of system: ProjectSystem) -> String? {
        guard projects.exists(path: system.attackTreePath) else { return nil }
        return try? projects.read(path: system.attackTreePath)
    }

    /// The labels the architecture's actions carry, in the order the file
    /// declares them. The governance file governs each one.
    static func actionLabels(
        of architectureText: String,
        useCases: CommandLineDependencies
    ) -> [String] {
        let read = useCases.architectureSources.read(architectureText)
        guard let source = read.source else { return [] }

        var labels: [String] = []
        for edge in source.mitigates {
            guard let label = edge.action?.label, labels.contains(label) == false else { continue }
            labels.append(label)
        }
        return labels
    }

    /// The rules the project states for itself, or nil when it holds no
    /// policy file. One file for the whole project.
    private func policyText(root: String) -> String? {
        guard let layout = try? projects.discover(root: root) else { return nil }
        guard projects.exists(path: layout.policyPath) else { return nil }
        return try? projects.read(path: layout.policyPath)
    }

    /// Who carries each accepted risk, or nil when the project holds no such
    /// file.
    private func governanceText(of system: ProjectSystem) -> String? {
        guard projects.exists(path: system.governancePath) else { return nil }
        return try? projects.read(path: system.governancePath)
    }

    /// Rewrites one system's `.attacktree` file in the canonical shape.
    ///
    /// False means the file could not be written. A file that does not parse
    /// is left as it is and its diagnostics are printed, the way the
    /// architecture file is.
    private func formatAttackTree(
        of system: ProjectSystem,
        isQuiet: Bool,
        output: (String) -> Void
    ) -> Bool {
        guard let text = treeText(of: system) else { return true }

        let read = attackTrees.read(text)
        guard let source = read.source, read.hasErrors == false else {
            for diagnostic in read.diagnostics {
                output(diagnostic.described(in: system.attackTreePath))
            }
            return false
        }

        let written = attackTrees.write(source)
        guard written != text else {
            if isQuiet == false { output("unchanged \(system.attackTreePath)") }
            return true
        }
        do {
            try projects.write(written, to: system.attackTreePath)
            if isQuiet == false { output("formatted \(system.attackTreePath)") }
            return true
        } catch {
            output("threatmodeller: \(Self.described(error))")
            return false
        }
    }

    /// Writes or merges every system's answers.
    private func compile(
        root: String,
        isQuiet: Bool,
        as machineOutput: MachineOutput,
        output: (String) -> Void
    ) -> Int32 {
        forEachSystem(root: root, output: output) { system, useCases in
            guard let architectureText = read(system.architecturePath, output) else {
                return .fileFault
            }
            let existing = projects.exists(path: system.controlsPath)
                ? try? projects.read(path: system.controlsPath)
                : nil

            // A split system is several architecture files and one controls
            // file beside each. It reads as one set and writes back per file.
            let parts = Self.parts(of: system, projects: projects)
            let heldControls = Self.controlsTexts(of: system, projects: projects)

            let response = useCases.compileControls().execute(
                CompileControlsRequest(
                    architectureText: architectureText,
                    controlsText: existing,
                    attackTreeText: treeText(of: system),
                    architectureParts: system.isSplit ? parts : [],
                    directoryName: system.isSplit ? system.name : nil,
                    controlsParts: system.isSplit ? heldControls : [:],
                    attackTreeTexts: system.isSplit ? Self.treeTexts(of: system, projects: projects) : []
                )
            )
            guard case .compiled(let text, let answered, let unanswered, let stale, let staleTrees, _, let warnings) = response else {
                guard case .refused(let diagnostics) = response else { return .didNotParse }
                for diagnostic in diagnostics {
                    output(Self.said(diagnostic, in: system.architecturePath, as: machineOutput))
                }
                return .didNotParse
            }

            do {
                if system.isSplit {
                    for (path, written) in Self.routedControls(
                        text,
                        of: system,
                        parts: parts,
                        held: heldControls,
                        useCases: useCases
                    ) {
                        try projects.write(written, to: path)
                    }
                } else {
                    try projects.write(text, to: system.controlsPath)
                }
            } catch {
                output("threatmodeller: \(Self.described(error))")
                return .fileFault
            }
            for warning in warnings {
                output(Self.said(warning, in: system.controlsPath, as: machineOutput))
            }

            // The governance file is written from the answers this compile
            // just wrote, so the two can never disagree about what is
            // accepted.
            let governed = useCases.compileGovernance().execute(
                CompileGovernanceRequest(
                    controlsText: text,
                    governanceText: governanceText(of: system),
                    actionLabels: Self.actionLabels(of: architectureText, useCases: useCases)
                )
            )
            switch governed {
            case .compiled(let governanceFile, let governedCount, let staleGovernance):
                if let governanceFile {
                    do {
                        try projects.write(governanceFile, to: system.governancePath)
                    } catch {
                        output("threatmodeller: \(Self.described(error))")
                        return .fileFault
                    }
                    if isQuiet == false {
                        output(
                            "\(system.governancePath): \(governedCount) governed,"
                                + " \(staleGovernance) stale"
                        )
                    }
                }
            case .refused(let diagnostics):
                for diagnostic in diagnostics {
                    output(Self.said(diagnostic, in: system.governancePath, as: machineOutput))
                }
                return .didNotParse
            }
            if isQuiet == false {
                output(
                    "\(system.controlsPath): \(answered) answered,"
                        + " \(unanswered) unanswered, \(stale) stale,"
                        + " \(staleTrees) stale trees"
                )
            }
            return .success
        }
    }

    /// Prints what the model scored at each sampled commit.
    ///
    /// The history is git: the project's own commits hold the files of that
    /// day. Nothing is stored, and nothing is read until a person asks.
    private func history(
        root: String,
        commits: Int,
        as machineOutput: MachineOutput,
        output: (String) -> Void
    ) -> Int32 {
        let catalogue: TechnologyCatalogue
        do {
            catalogue = try makeCatalogue()
        } catch {
            output("threatmodeller: the catalogue could not be loaded: \(error)")
            return ExitCode.fileFault.rawValue
        }

        let read = ReadRiskHistory(
            projects: projects,
            history: history,
            catalogue: catalogue,
            architectureSources: architecture,
            controlsSources: controls,
            attackTreeSources: attackTrees,
            governanceSources: HclGovernanceSource(),
            layout: LayOutModel()
        ).execute(ReadRiskHistoryRequest(root: root, commits: commits))

        switch read {
        case .read(let history):
            let rows = history.rows
            guard rows.isEmpty == false else {
                output("threatmodeller: no commit touched a threat model file")
                return ExitCode.success.rawValue
            }
            for row in rows {
                output(Self.said(row))
            }
            if history.truncated {
                output(
                    "threatmodeller: the newest \(rows.count) commits; the project holds more"
                )
            }
            return ExitCode.success.rawValue
        case .notARepository(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.success.rawValue
        case .noSuchSystem:
            output("threatmodeller: this project holds no such system")
            return ExitCode.fileFault.rawValue
        case .cannotRead(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.fileFault.rawValue
        }
    }

    /// One history row, as a person reads it.
    static func said(_ row: RiskHistoryRow) -> String {
        let head = "\(MarkdownRiskOverTime.day(row.commit.date))  \(row.commit.shortHash)"
            + "  \(row.commit.author)"
        guard let numbers = row.numbers else { return "\(head)  did not parse" }

        let critical = numbers.byLevel[RiskLevel.critical.rawValue] ?? 0
        let high = numbers.byLevel[RiskLevel.high.rawValue] ?? 0
        return "\(head)  total \(numbers.totalScore)  worst \(numbers.worstScore)"
            + "  critical \(critical)  high \(high)  accepted \(numbers.acceptedRisks)"
            + "  trees \(numbers.openAttackTrees)  \(numbers.catalogueTag ?? "\u{2014}")"
    }

    /// Says what a pull request has not answered.
    ///
    /// `plain` writes the lines a person reads. `github` writes the workflow
    /// commands a pull request shows beside the line they name. `json` writes
    /// one object at the end, so nothing else may write a plain line while it
    /// runs.
    private func check(
        root: String,
        tolerance: String?,
        as machineOutput: MachineOutput,
        output: (String) -> Void
    ) -> Int32 {
        var checked: [CheckedSystemJSON] = []
        var messages: [String] = []
        // `json` writes one object at the end, so nothing the run says on the
        // way may reach the output before it.
        func say(_ line: String) {
            if machineOutput == .json { messages.append(line) } else { output(line) }
        }

        // The window's check summary reads the same use case, so the two say
        // the same words about the same project.
        let code = forEachSystem(root: root, output: say) { system, useCases in
            let response = CheckSystem(projects: projects, checks: useCases.checkControlAnswers())
                .execute(
                    CheckSystemRequest(root: root, systemName: system.name, tolerance: tolerance)
                )
            guard case .checked(let found) = response else {
                say("threatmodeller: this project holds no such system")
                return .fileFault
            }
            if let reason = found.unreadable {
                say("threatmodeller: \(reason)")
                return .fileFault
            }

            guard found.didParse else {
                for diagnostic in found.diagnostics {
                    switch machineOutput {
                    case .plain:
                        output(diagnostic.described(in: found.diagnosticsPath))
                    case .github:
                        output(GitHubOutput.line(diagnostic, in: found.diagnosticsPath))
                    case .json:
                        messages.append(diagnostic.described(in: found.diagnosticsPath))
                    }
                }
                return .didNotParse
            }

            let unansweredLines = found.unanswered.map { threat in
                ControlsStanzaLines.line(
                    threatId: threat.threatId,
                    sourceKind: threat.sourceKind,
                    sourceId: threat.sourceId,
                    in: found.controlsText
                )
            }

            switch machineOutput {
            case .plain:
                for finding in found.findings {
                    output(finding.said)
                }
                if let toleranceLine = found.toleranceLine {
                    output(toleranceLine)
                }
                if found.passes {
                    output(found.allAnsweredLine)
                }
            case .github:
                for diagnostic in found.diagnostics {
                    output(GitHubOutput.line(diagnostic, in: found.controlsPath))
                }
                for (threat, line) in zip(found.unanswered, unansweredLines) {
                    output(
                        GitHubOutput.line(
                            severity: .error,
                            file: found.controlsPath,
                            line: line,
                            column: 1,
                            message: threat.described
                        )
                    )
                }
                for key in found.stale {
                    output(
                        GitHubOutput.line(
                            severity: .error,
                            file: found.controlsPath,
                            line: 1,
                            column: 1,
                            message: "\(key) is answered but no longer raised"
                        )
                    )
                }
                for described in found.staleTrees {
                    output(
                        GitHubOutput.line(
                            severity: .error,
                            file: found.controlsPath,
                            line: 1,
                            column: 1,
                            message: described
                        )
                    )
                }
                for described in found.governance {
                    output(
                        GitHubOutput.line(
                            severity: .error,
                            file: found.governancePath,
                            line: 1,
                            column: 1,
                            message: described
                        )
                    )
                }
            case .json:
                break
            }

            checked.append(
                CheckedSystemJSON(
                    name: found.name,
                    tolerance: found.tolerance,
                    diagnostics: found.diagnostics.map {
                        CheckedSystemJSON.DiagnosticJSON(
                            severity: $0.severity.rawValue,
                            file: found.controlsPath,
                            line: $0.line,
                            column: $0.column,
                            message: $0.message
                        )
                    },
                    unanswered: zip(found.unanswered, unansweredLines).map { threat, line in
                        CheckedSystemJSON.UnansweredJSON(
                            threatId: threat.threatId,
                            sourceKind: threat.sourceKind,
                            sourceId: threat.sourceId,
                            riskLevel: threat.riskLevel,
                            file: found.controlsPath,
                            line: line
                        )
                    },
                    stale: found.stale,
                    staleTrees: found.staleTrees,
                    governance: found.governance
                )
            )

            return found.passes ? .success : .unanswered
        }

        if machineOutput == .json {
            output(CheckReportJSON(systems: checked, messages: messages).text())
        }
        return code
    }

    /// Writes the Markdown report for every system.
    private func report(
        root: String,
        into: String?,
        templatePath: String?,
        diagramLanguage: String?,
        wantsHtml: Bool,
        isQuiet: Bool,
        commits: Int = ReadRiskHistory.defaultCommits,
        output: (String) -> Void
    ) -> Int32 {
        // One resolution for every writer: the window's report paths read the
        // template through the same use case.
        var template: ReportTemplate?
        switch ReadReportTemplate(projects: projects, policies: HclPolicySource())
            .execute(ReadReportTemplateRequest(root: root, statedPath: templatePath)) {
        case .none:
            break
        case .found(let found):
            template = found
        case .missing(let path):
            output("threatmodeller: there is no template at \(path)")
            return ExitCode.fileFault.rawValue
        case .didNotParse(let path, let diagnostics):
            for diagnostic in diagnostics {
                output(diagnostic.described(in: path))
            }
            return ExitCode.didNotParse.rawValue
        }

        if let diagramLanguage, diagramLanguage != TextDiagramWriter.Language.mermaid.rawValue {
            output(
                "threatmodeller: there is no report diagram language"
                    + " \"\(diagramLanguage)\"; this application writes mermaid"
            )
            return ExitCode.didNotParse.rawValue
        }

        return forEachSystem(root: root, output: output) { system, useCases in
            guard let architectureText = read(system.architecturePath, output) else {
                return .fileFault
            }

            let imported = useCases.importArchitecture()
                .execute(
                    ImportArchitectureRequest(
                        text: architectureText,
                        attackTreeText: treeText(of: system),
                        parts: system.isSplit ? Self.parts(of: system, projects: projects) : [],
                        directoryName: system.isSplit ? system.name : nil,
                        attackTreeTexts: system.isSplit
                            ? Self.treeTexts(of: system, projects: projects)
                            : []
                    )
                )
            guard case .imported = imported else {
                guard case .refused(let diagnostics) = imported else { return .didNotParse }
                for diagnostic in diagnostics {
                    output(diagnostic.described(in: system.architecturePath))
                }
                return .didNotParse
            }

            if projects.exists(path: system.controlsPath),
               let controlsText = try? projects.read(path: system.controlsPath) {
                let applied = useCases.applyControlAnswers()
                    .execute(ApplyControlAnswersRequest(text: controlsText))
                switch applied {
                case .refused(let diagnostics):
                    for diagnostic in diagnostics {
                        output(diagnostic.described(in: system.controlsPath))
                    }
                    return .didNotParse
                case .applied(_, let warnings):
                    for warning in warnings {
                        output(warning.described(in: system.controlsPath))
                    }
                }
            }

            // The rules the project states for itself, so the report says
            // whether this system keeps each one.
            if let policyText = policyText(root: root) {
                switch useCases.applyPolicy().execute(ApplyPolicyRequest(text: policyText)) {
                case .applied:
                    break
                case .refused(let diagnostics):
                    for diagnostic in diagnostics {
                        output(diagnostic.described(in: ProjectConvention.policyFileName))
                    }
                    return .didNotParse
                }
            }

            // The history is git, and reading it compiles the model once per
            // sampled commit, so `--commits 0` turns it off.
            var historyRead = RiskHistory()
            if commits > 0 {
                let read = ReadRiskHistory(
                    projects: projects,
                    history: history,
                    catalogue: useCases.catalogue,
                    architectureSources: architecture,
                    controlsSources: controls,
                    attackTreeSources: attackTrees,
                    governanceSources: HclGovernanceSource(),
                    layout: LayOutModel()
                ).execute(ReadRiskHistoryRequest(root: root, commits: commits))
                if case .read(let found) = read { historyRead = found }
            }

            // A picture of each of the top residual threats, beside the
            // report. The core cannot draw one: drawing depends on the core.
            let canvas = useCases.viewThreatModel().execute(ViewThreatModelRequest())
            let assessment = useCases.assessThreatModel().execute(AssessThreatModelRequest())

            // What changed between the previous sampled commit and the
            // working tree. A project with one commit compares against
            // nothing and the report writes no such section.
            var change: RiskChange?
            if historyRead.rows.count >= 2 || historyRead.rows.count == 1 {
                guard case .compared(let compared) = CompareRiskToCommit().execute(
                    CompareRiskToCommitRequest(
                        now: assessment.threats.map(ReadRiskHistory.compared),
                        then: historyRead.previousThreats,
                        catalogueNow: useCases.catalogue.version().tag,
                        catalogueThen: historyRead.previousCatalogueTag
                    )
                ) else { return .fileFault }
                change = compared.isEmpty ? nil : compared
            }

            let report = useCases.buildThreatModelReport()
                .execute(
                    BuildThreatModelReportRequest(
                        history: historyRead.rows,
                        historyTruncated: historyRead.truncated,
                        change: change
                    )
                ).report
            let drawn = DiagramBuilder.Model(
                components: canvas.components,
                connections: canvas.connections,
                zones: canvas.zones,
                risks: ElementRiskRollup.byElement(
                    assessment.threats,
                    levelOrder: assessment.severities.map(\.id)
                ),
                guards: EdgeGuards.byElement(assessment.threats)
            )
            let pictures = ThreatDiagrams.pictures(
                of: drawn,
                for: report.rollups.topResidual,
                stem: system.name
            )
            // A picture of each control as well, for a reader scrutinising
            // what one control carries rather than what one threat sits on.
            let controls = ThreatDiagrams.controlPictures(
                of: drawn,
                for: report.protectionDependencies,
                stem: system.name
            )

            // A report written in a diagram language holds the diagram
            // itself, so a wiki renders it and no image file sits beside the
            // report.
            let wantsText = diagramLanguage != nil
            let threatDiagrams = wantsText
                ? ThreatDiagrams.mermaidTexts(of: drawn, for: report.rollups.topResidual)
                : [:]
            let controlDiagrams = wantsText
                ? ThreatDiagrams.controlMermaidTexts(
                    of: drawn,
                    for: report.protectionDependencies
                )
                : [:]

            let threatPictures = wantsText
                ? [:]
                : Dictionary(uniqueKeysWithValues: pictures.map { ($0.key, $0.fileName) })
            let controlPictures = wantsText
                ? [:]
                : Dictionary(uniqueKeysWithValues: controls.map { ($0.protectorId, $0.fileName) })
            // The graph is written beside the report, the way the threat
            // pictures are, and only when the history holds enough to draw.
            let chart = RiskOverTimeChart.svg(of: historyRead.rows)
            let chartFileName = chart.isEmpty ? nil : "\(system.name)-risk-over-time.svg"

            let markdown = useCases.exportModelAsMarkdown()
                .execute(
                    ExportModelAsMarkdownRequest(
                        threatPictures: threatPictures,
                        controlPictures: controlPictures,
                        threatDiagrams: threatDiagrams,
                        controlDiagrams: controlDiagrams,
                        template: template,
                        riskOverTimePicture: chartFileName,
                        history: historyRead.rows,
                        historyTruncated: historyRead.truncated,
                        change: change
                    )
                )
            let path = into.map { ProjectConvention.path($0, "\(system.name).md") }
                ?? system.reportPath
            let beside = String(path.dropLast("\(system.name).md".count))

            if let chartFileName {
                do {
                    try projects.write(chart, to: beside + chartFileName)
                } catch {
                    output("threatmodeller: \(Self.described(error))")
                    return .fileFault
                }
            }

            // A report holding the diagrams needs no picture beside it.
            for picture in (wantsText ? [] : pictures) {
                do {
                    try projects.write(picture.svg, to: beside + picture.fileName)
                } catch {
                    output("threatmodeller: \(Self.described(error))")
                    return .fileFault
                }
            }
            for picture in (wantsText ? [] : controls) {
                do {
                    try projects.write(picture.svg, to: beside + picture.fileName)
                } catch {
                    output("threatmodeller: \(Self.described(error))")
                    return .fileFault
                }
            }
            do {
                try projects.write(markdown.markdown, to: path)
            } catch {
                output("threatmodeller: \(Self.described(error))")
                return .fileFault
            }

            var htmlPath: String?
            if wantsHtml {
                // The page carries every picture inside it, so a reader opens
                // one file and needs nothing beside it.
                var sources = Dictionary(
                    uniqueKeysWithValues: (pictures.map { ($0.fileName, $0.svg) })
                )
                for picture in controls { sources[picture.fileName] = picture.svg }

                let page = useCases.exportModelAsHtml().execute(
                    ExportModelAsHtmlRequest(
                        threatPictures: threatPictures,
                        controlPictures: controlPictures,
                        pictureSources: sources,
                        wholePicture: SvgWriter.svg(of: DiagramBuilder.drawing(of: drawn)),
                        template: template
                    )
                )
                // Beside the report, named after the system the way every
                // other file this verb writes is. `page.fileName` names what a
                // save panel offers, which is the model's own name.
                let written = beside + "\(system.name).html"
                do {
                    try projects.write(page.html, to: written)
                } catch {
                    output("threatmodeller: \(Self.described(error))")
                    return .fileFault
                }
                htmlPath = written
            }

            if isQuiet == false {
                output("wrote \(path)")
                if let htmlPath {
                    output("wrote \(htmlPath)")
                }
                if pictures.isEmpty == false {
                    output("wrote \(pictures.count) threat diagrams beside it")
                }
                if controls.isEmpty == false {
                    output("wrote \(controls.count) control diagrams beside it")
                }
            }
            return .success
        }
    }

    /// What `draw` writes.
    public enum DiagramFormat: String, Sendable, CaseIterable {
        case svg
        case png
        case mermaid
        case dot
        case d2

        /// The extension a file of this format takes. Mermaid writes `.mmd`,
        /// which is what an editor and a wiki read.
        var fileExtension: String {
            TextDiagramWriter.Language(rawValue: rawValue)?.fileExtension ?? rawValue
        }

        /// The language this format writes, or nil for a picture.
        var language: TextDiagramWriter.Language? {
            TextDiagramWriter.Language(rawValue: rawValue)
        }
    }

    /// Writes every system as a picture.
    ///
    /// SVG is written by this package, so it works wherever the tool runs. PNG
    /// needs a drawing engine, which only Apple's platforms supply here, so a
    /// Linux build says so rather than writing nothing.
    /// Speaks the Language Server Protocol over standard input and output.
    ///
    /// The protocol frames each message with a `Content-Length` header, so
    /// this reads that header, reads that many bytes, and writes its answers
    /// framed the same way.
    private func serveLsp() -> Int32 {
        let server = LanguageServer(projects: projects, catalogue: makeCatalogue)
        let input = FileHandle.standardInput
        var held = Data()

        while true {
            // A header ends at a blank line.
            guard let headerEnd = Self.headerEnd(in: held) else {
                let read = input.availableData
                if read.isEmpty { return ExitCode.success.rawValue }
                held += read
                continue
            }
            let header = String(decoding: held[held.startIndex ..< headerEnd.lowerBound], as: UTF8.self)
            guard let length = Self.contentLength(of: header) else {
                held = Data(held[headerEnd.upperBound...])
                continue
            }
            var body = Data(held[headerEnd.upperBound...])
            while body.count < length {
                let read = input.availableData
                if read.isEmpty { return ExitCode.success.rawValue }
                body += read
            }
            let message = String(decoding: body.prefix(length), as: UTF8.self)
            held = Data(body.dropFirst(length))

            // The frame states the body's length and the body follows the
            // blank line with nothing between, so this writes the bytes
            // itself rather than a line at a time.
            for answer in server.answer(to: message) {
                let body = Data(answer.utf8)
                let header = Data("Content-Length: \(body.count)\r\n\r\n".utf8)
                FileHandle.standardOutput.write(header + body)
            }
            if message.contains("\"method\":\"exit\"") { return ExitCode.success.rawValue }
        }
    }

    /// Where a message's header ends, which is at the blank line.
    static func headerEnd(in data: Data) -> Range<Data.Index>? {
        data.range(of: Data("\r\n\r\n".utf8)) ?? data.range(of: Data("\n\n".utf8))
    }

    /// How many bytes the body holds, from the header.
    static func contentLength(of header: String) -> Int? {
        for line in header.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2,
                  parts[0].trimmingCharacters(in: .whitespaces).lowercased() == "content-length"
            else { continue }
            return Int(parts[1].trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return nil
    }

    /// Serves the Model Context Protocol over standard input and output.
    ///
    /// One request a line, one answer a line. Every tool runs the verb a
    /// person runs, so an assistant reads the application's own answers.
    private func serveMcp(
        root: String,
        allowsWrites: Bool,
        output: (String) -> Void
    ) -> Int32 {
        let server = McpServer(
            application: self,
            projects: projects,
            root: root,
            allowsWrites: allowsWrites
        )
        while let line = readLine(strippingNewline: true) {
            guard line.trimmingCharacters(in: .whitespaces).isEmpty == false else { continue }
            if let answer = server.answer(to: line) { output(answer) }
        }
        return ExitCode.success.rawValue
    }

    /// Draws what a Terraform state holds.
    ///
    /// The state arrives on standard input, the way `terraform show -json`
    /// writes it, so nothing here reaches a cloud account.
    private func importing(
        words: [String],
        isQuiet: Bool,
        output: (String) -> Void
    ) -> Int32 {
        guard words.first == "terraform" else {
            output("threatmodeller: import takes terraform")
            return ExitCode.didNotParse.rawValue
        }
        let root = words.dropFirst().first { $0.hasPrefix("-o:") == false } ?? "."

        let stateText = standardInput()
        guard stateText.isEmpty == false else {
            output("threatmodeller: no state arrived on standard input")
            return ExitCode.didNotParse.rawValue
        }

        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: root)
        } catch {
            output("threatmodeller: \(Self.described(error))")
            return ExitCode.fileFault.rawValue
        }

        // The one system a project holds, or a new one named after the
        // directory. A project of many systems is told which to import into
        // by naming that system's own directory as the root.
        let system = layout.systems.first
        // A project with no system yet takes the project's own name, which is
        // the directory holding `threatmodel/`, not that directory itself.
        let name = system?.name ?? Self.projectName(root: root, layout: layout)
        let path = system?.architecturePath
            ?? ProjectConvention.path(layout.directory, "\(name).arch")
        let held = system.flatMap { try? projects.read(path: $0.architecturePath) }

        let response = ImportTerraform(sources: architecture).execute(
            ImportTerraformRequest(
                stateText: stateText,
                architectureText: held,
                systemName: name
            )
        )

        switch response {
        case .unreadableState:
            output("threatmodeller: the state is not the JSON `terraform show -json` writes")
            return ExitCode.didNotParse.rawValue
        case .refused(let diagnostics):
            for diagnostic in diagnostics { output(diagnostic.described(in: path)) }
            return ExitCode.didNotParse.rawValue
        case .nothingToImport(let unmapped):
            for line in Self.unmappedLines(unmapped) { output(line) }
            output("threatmodeller: this state holds nothing this application draws")
            return ExitCode.success.rawValue
        case .imported(let text, let added, let removed, let components, let zones, let flows, let unmapped):
            do {
                try projects.write(text, to: path)
            } catch {
                output("threatmodeller: \(Self.described(error))")
                return ExitCode.fileFault.rawValue
            }
            if isQuiet == false {
                for id in added { output("added \(id)") }
                for id in removed {
                    output("removed \(id), which the state no longer holds")
                }
                for line in Self.unmappedLines(unmapped) { output(line) }
                output(
                    "imported \(components) components, \(zones) zones and \(flows) flows"
                        + " into \(path)"
                )
            }
            return ExitCode.success.rawValue
        }
    }

    /// What a project with no system yet calls the system this import writes.
    static func projectName(root: String, layout: ProjectLayout) -> String {
        let parts = layout.directory.split(separator: "/").map(String.init)
        let named = parts.last == ProjectConvention.conventionDirectoryName
            ? parts.dropLast().last
            : parts.last
        guard let named, named.isEmpty == false, named != "." else { return "system" }
        return named
    }

    /// One line naming every resource type this application does not map, and
    /// how many of each the state held.
    static func unmappedLines(_ unmapped: [(type: String, count: Int)]) -> [String] {
        guard unmapped.isEmpty == false else { return [] }
        let total = unmapped.reduce(0) { $0 + $1.count }
        let named = unmapped.map { "\($0.type) (\($0.count))" }.joined(separator: ", ")
        return ["\(total) resources have no mapping: \(named)"]
    }

    /// The whole of standard input, as text.
    public static func everyLineOfStandardInput() -> String {
        var text = ""
        while let line = readLine(strippingNewline: false) { text += line }
        return text
    }

    /// Says what each system in a project holds and what it scores.
    ///
    /// One resolve per system and no layout: the numbers come from the
    /// assessment, and nothing here places a component. A system whose files
    /// do not parse takes a row that says `unparsed`, and the verb still
    /// exits 0, because `check` is the verb that fails.
    private func list(
        root: String,
        fields fieldWords: String?,
        sort sortWord: String?,
        wantsHeader: Bool,
        wantsJson: Bool,
        output: (String) -> Void
    ) -> Int32 {
        var fields = SystemList.Field.allCases
        if let fieldWords {
            switch SystemList.fields(named: fieldWords) {
            case .success(let picked):
                fields = picked
            case .failure(let word):
                output(
                    "threatmodeller: there is no column \"\(word)\";"
                        + " this application writes \(SystemList.Field.names)"
                )
                return ExitCode.didNotParse.rawValue
            }
        }

        var sortField: SystemList.Field?
        if let sortWord {
            guard let field = SystemList.Field(rawValue: sortWord) else {
                output(
                    "threatmodeller: there is no column \"\(sortWord)\";"
                        + " this application writes \(SystemList.Field.names)"
                )
                return ExitCode.didNotParse.rawValue
            }
            sortField = field
        }

        // A diagnostic about one system's file is not this verb's output: an
        // unparsed system takes a row saying so. What the walk says about the
        // project itself is written, because then there are no rows at all.
        var rows: [SystemRow] = []
        var said: [String] = []
        let code = forEachSystem(root: root, output: { said.append($0) }) { system, useCases in
            rows.append(row(of: system, useCases: useCases))
            return .success
        }
        guard code == ExitCode.success.rawValue, rows.isEmpty == false else {
            for line in said { output(line) }
            return code
        }

        if let sortField { rows = SystemList.sorted(rows, by: sortField) }

        if wantsJson {
            output(SystemList.json(rows, fields: fields))
        } else {
            for line in SystemList.plain(rows, fields: fields, wantsHeader: wantsHeader) {
                output(line)
            }
        }
        return ExitCode.success.rawValue
    }

    /// One system's row. Nothing here writes a file or draws anything.
    private func row(of system: ProjectSystem, useCases: CommandLineDependencies) -> SystemRow {
        let unparsed = SystemRow(
            name: system.name,
            file: system.headerPath,
            isUnparsed: true
        )
        guard let architectureText = try? projects.read(path: system.architecturePath) else {
            return unparsed
        }

        let imported = useCases.importArchitecture()
            .execute(
                ImportArchitectureRequest(
                    text: architectureText,
                    attackTreeText: treeText(of: system),
                    parts: system.isSplit ? Self.parts(of: system, projects: projects) : [],
                    directoryName: system.isSplit ? system.name : nil,
                    attackTreeTexts: system.isSplit
                        ? Self.treeTexts(of: system, projects: projects)
                        : []
                )
            )
        guard case .imported(_, _, let catalogueTag) = imported else { return unparsed }

        if projects.exists(path: system.controlsPath),
           let controlsText = try? projects.read(path: system.controlsPath) {
            _ = useCases.applyControlAnswers()
                .execute(ApplyControlAnswersRequest(text: controlsText))
        }

        let canvas = useCases.viewThreatModel().execute(ViewThreatModelRequest())
        let assessment = useCases.assessThreatModel().execute(AssessThreatModelRequest())
        let worst = assessment.threats.max { $0.riskScore < $1.riskScore }
        // Who owns the system and when it was last read again are the file's
        // own words, so they are read from the source rather than from a
        // report nobody asked this verb to build.
        let source = architecture.read(architectureText).source

        return SystemRow(
            name: system.name,
            file: system.headerPath,
            owner: source?.owner ?? "",
            components: canvas.components.count,
            zones: canvas.zones.count,
            flows: canvas.connections.count,
            threats: assessment.threats.count,
            unanswered: assessment.threats.filter(Self.isUnanswered).count,
            accepted: assessment.threats
                .filter { $0.controls.contains { $0.statusId == ControlStatus.accepted.rawValue } }
                .count,
            worstScore: worst?.riskScore ?? 0,
            worstLevel: worst?.riskLevel ?? "",
            catalogueTag: catalogueTag ?? "",
            reviewed: source?.reviewed ?? ""
        )
    }

    /// A threat nobody has answered: no control carries an answer, and no
    /// compensating control stands. The report counts the same way.
    private static func isUnanswered(_ threat: AssessedThreat) -> Bool {
        guard threat.compensatingLabels.isEmpty else { return false }
        return threat.controls.contains { $0.statusId != ControlStatus.notImplemented.rawValue }
            == false
    }

    /// The shapes `export` writes.
    enum ExportFormat: String, CaseIterable {
        case json
        case otm
        case threatcl

        static var names: String {
            allCases.map(\.rawValue).joined(separator: "|")
        }
    }

    /// Writes the assessed model as data another program reads.
    ///
    /// `--stdout` writes one system to standard output, so a pipeline reads it
    /// without a temporary directory. A project holding more than one system
    /// then says so rather than running the two together.
    private func export(
        root: String,
        into: String?,
        format: String,
        wantsStandardOutput: Bool,
        isQuiet: Bool,
        output: (String) -> Void
    ) -> Int32 {
        guard let shape = ExportFormat(rawValue: format) else {
            output(
                "threatmodeller: there is no export format \"\(format)\";"
                    + " this application writes \(ExportFormat.names)"
            )
            return ExitCode.didNotParse.rawValue
        }

        var written = 0
        let code = forEachSystem(root: root, output: output) { system, useCases in
            guard let architectureText = read(system.architecturePath, output) else {
                return .fileFault
            }

            let imported = useCases.importArchitecture()
                .execute(
                    ImportArchitectureRequest(
                        text: architectureText,
                        attackTreeText: treeText(of: system),
                        parts: system.isSplit ? Self.parts(of: system, projects: projects) : [],
                        directoryName: system.isSplit ? system.name : nil,
                        attackTreeTexts: system.isSplit
                            ? Self.treeTexts(of: system, projects: projects)
                            : []
                    )
                )
            guard case .imported = imported else {
                guard case .refused(let diagnostics) = imported else { return .didNotParse }
                for diagnostic in diagnostics {
                    output(diagnostic.described(in: system.architecturePath))
                }
                return .didNotParse
            }

            if projects.exists(path: system.controlsPath),
               let controlsText = try? projects.read(path: system.controlsPath) {
                _ = useCases.applyControlAnswers()
                    .execute(ApplyControlAnswersRequest(text: controlsText))
            }

            if let policyText = policyText(root: root) {
                _ = useCases.applyPolicy().execute(ApplyPolicyRequest(text: policyText))
            }

            // The file is named after the system's own file, the way the
            // report is, so a project's files sort together.
            let text: String
            let fileName: String
            switch shape {
            case .json:
                text = useCases.exportModelAsJson().execute(ExportModelAsJsonRequest()).json
                fileName = "\(system.name).json"
            case .otm:
                text = useCases.exportModelAsOtm().execute(ExportModelAsOtmRequest()).json
                fileName = "\(system.name).otm.json"
            case .threatcl:
                text = useCases.exportModelAsThreatcl()
                    .execute(ExportModelAsThreatclRequest()).hcl
                fileName = "\(system.name).hcl"
            }

            if wantsStandardOutput {
                written += 1
                guard written == 1 else {
                    output(
                        "threatmodeller: this project holds more than one system,"
                            + " so --stdout writes none; name one root or drop the flag"
                    )
                    return .didNotParse
                }
                output(text.hasSuffix("\n") ? String(text.dropLast()) : text)
                return .success
            }

            let path = into.map { ProjectConvention.path($0, fileName) }
                ?? ProjectConvention.path(
                    String(system.architecturePath.dropLast(system.name.count + 5)),
                    fileName
                )
            do {
                try projects.write(text, to: path)
            } catch {
                output("threatmodeller: \(Self.described(error))")
                return .fileFault
            }
            if isQuiet == false { output("wrote \(path)") }
            return .success
        }
        return code
    }

    private func draw(
        root: String,
        into: String?,
        wants: Set<DiagramFormat>,
        isQuiet: Bool,
        output: (String) -> Void
    ) -> Int32 {
        let formats = wants.isEmpty ? [DiagramFormat.svg] : wants

        return forEachSystem(root: root, output: output) { system, useCases in
            guard let architectureText = read(system.architecturePath, output) else {
                return .fileFault
            }

            let imported = useCases.importArchitecture()
                .execute(
                    ImportArchitectureRequest(
                        text: architectureText,
                        attackTreeText: treeText(of: system),
                        parts: system.isSplit ? Self.parts(of: system, projects: projects) : [],
                        directoryName: system.isSplit ? system.name : nil,
                        attackTreeTexts: system.isSplit
                            ? Self.treeTexts(of: system, projects: projects)
                            : []
                    )
                )
            guard case .imported = imported else {
                guard case .refused(let diagnostics) = imported else { return .didNotParse }
                for diagnostic in diagnostics {
                    output(diagnostic.described(in: system.architecturePath))
                }
                return .didNotParse
            }

            if projects.exists(path: system.controlsPath),
               let controlsText = try? projects.read(path: system.controlsPath) {
                _ = useCases.applyControlAnswers()
                    .execute(ApplyControlAnswersRequest(text: controlsText))
            }

            let canvas = useCases.viewThreatModel().execute(ViewThreatModelRequest())
            let assessment = useCases.assessThreatModel().execute(AssessThreatModelRequest())
            let drawn = DiagramBuilder.Model(
                components: canvas.components,
                connections: canvas.connections,
                zones: canvas.zones,
                risks: ElementRiskRollup.byElement(
                    assessment.threats,
                    levelOrder: assessment.severities.map(\.id)
                ),
                guards: EdgeGuards.byElement(assessment.threats)
            )
            let drawing = DiagramBuilder.drawing(of: drawn)

            for format in formats.sorted(by: { $0.rawValue < $1.rawValue }) {
                let name = "\(system.name).\(format.fileExtension)"
                let path = into.map { ProjectConvention.path($0, name) }
                    ?? ProjectConvention.path(
                        String(system.architecturePath.dropLast(system.name.count + 5)),
                        name
                    )

                switch format {
                case .svg:
                    do {
                        try projects.write(SvgWriter.svg(of: drawing), to: path)
                    } catch {
                        output("threatmodeller: \(Self.described(error))")
                        return .fileFault
                    }
                case .png:
                    guard let bytes = PngWriter.png(of: drawing) else {
                        output("threatmodeller: this build writes no PNG; write SVG instead")
                        return .fileFault
                    }
                    do {
                        try projects.write(bytes: bytes, to: path)
                    } catch {
                        output("threatmodeller: \(Self.described(error))")
                        return .fileFault
                    }
                case .mermaid, .dot, .d2:
                    guard let language = format.language else { return .fileFault }
                    do {
                        try projects.write(
                            TextDiagramWriter.text(of: drawn, in: language),
                            to: path
                        )
                    } catch {
                        output("threatmodeller: \(Self.described(error))")
                        return .fileFault
                    }
                }

                if isQuiet == false { output("wrote \(path)") }
            }

            return .success
        }
    }

    /// Runs one verb over every system, and returns the worst result.
    private func forEachSystem(
        root: String,
        output: (String) -> Void,
        _ act: (ProjectSystem, CommandLineDependencies) -> ExitCode
    ) -> Int32 {
        let layout: ProjectLayout
        do {
            layout = try projects.discover(root: root)
        } catch {
            output("threatmodeller: \(Self.described(error))")
            return ExitCode.fileFault.rawValue
        }

        guard layout.systems.isEmpty == false else {
            output("threatmodeller: \(layout.directory) holds no .arch files")
            return ExitCode.success.rawValue
        }

        let catalogue: TechnologyCatalogue
        do {
            catalogue = try makeCatalogue()
        } catch {
            output("threatmodeller: the catalogue could not be loaded: \(error)")
            return ExitCode.fileFault.rawValue
        }

        // A project's libraries are read once and every system reads them all.
        let store = LibraryStore()
        let merged = MergedCatalogue(base: catalogue, store: store)
        let libraryDirectory = ProjectConvention.path(
            layout.directory,
            ProjectConvention.libraryDirectory
        )
        switch LoadLibraries(
            projects: projects,
            sources: HclLibrarySource(),
            catalogue: catalogue
        ).execute(LoadLibrariesRequest(root: root)) {
        case .loaded(let libraries, let warnings):
            store.set(libraries)
            for warning in warnings {
                output("threatmodeller: \(warning.message)")
            }
        case .refused(let fileName, let diagnostics):
            for diagnostic in diagnostics {
                output(
                    diagnostic.described(in: ProjectConvention.path(libraryDirectory, fileName))
                )
            }
            return ExitCode.didNotParse.rawValue
        case .notAProject(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.fileFault.rawValue
        }

        var worst = ExitCode.success
        for system in layout.systems {
            let useCases = CommandLineDependencies(
                catalogue: merged,
                mitre: mitreActors,
                architectureSources: architecture,
                controlsSources: controls,
                history: history
            )
            let code = act(system, useCases)
            if code != .success { worst = code }
        }
        return worst.rawValue
    }

    // MARK: the library verbs

    private func library(words: [String], isForced: Bool, output: (String) -> Void) -> Int32 {
        guard let operation = words.first else {
            output(Self.usage)
            return ExitCode.didNotParse.rawValue
        }
        let rest = Array(words.dropFirst())

        switch operation {
        case "add":
            guard rest.count >= 2 else {
                output("threatmodeller: library add takes a repository and a tag")
                return ExitCode.didNotParse.rawValue
            }
            return add(repository: rest[0], tag: rest[1], root: rest.count > 2 ? rest[2] : ".", output: output)
        case "update":
            // `update <label> <root>`, `update <root>` or `update`.
            let label = rest.count >= 2 ? rest[0] : nil
            let root = rest.count >= 2 ? rest[1] : (rest.first ?? ".")
            return update(label: label, root: root, output: output)
        case "remove":
            guard let label = rest.first else {
                output("threatmodeller: library remove takes a library's name")
                return ExitCode.didNotParse.rawValue
            }
            return remove(
                label: label,
                root: rest.count > 1 ? rest[1] : ".",
                isForced: isForced,
                output: output
            )
        case "list":
            return list(root: rest.first ?? ".", output: output)
        case "verify":
            return verify(root: rest.first ?? ".", output: output)
        case "outdated":
            return outdated(root: rest.first ?? ".", output: output)
        default:
            output("threatmodeller: there is no library operation \"\(operation)\"")
            output(Self.usage)
            return ExitCode.didNotParse.rawValue
        }
    }

    private func adds() -> AddLibrary {
        AddLibrary(projects: projects, fetcher: fetcher, sources: libraries)
    }

    private func add(
        repository: String,
        tag: String,
        root: String,
        output: (String) -> Void
    ) -> Int32 {
        switch adds().execute(
            AddLibraryRequest(root: root, repository: repository, tag: tag)
        ) {
        case .added(let label, let files):
            output("\(label): \(files.joined(separator: ", ")) at \(tag)")
            return ExitCode.success.rawValue
        case .cannotFetch(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.fetchFailed.rawValue
        case .refused(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.didNotParse.rawValue
        case .notAProject(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.fileFault.rawValue
        case .cannotWrite(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.fileFault.rawValue
        }
    }

    private func update(label: String?, root: String, output: (String) -> Void) -> Int32 {
        switch UpdateLibraries(projects: projects, adds: adds()).execute(
            UpdateLibrariesRequest(root: root, label: label)
        ) {
        case .updated(let labels):
            if labels.isEmpty {
                output("threatmodeller: this project holds no library")
            } else {
                for updated in labels { output("\(updated): read again") }
            }
            return ExitCode.success.rawValue
        case .noSuchLibrary:
            output("threatmodeller: this project holds no library called \"\(label ?? "")\"")
            return ExitCode.fileFault.rawValue
        case .cannotFetch(let label, let reason):
            output("threatmodeller: \(label): \(reason)")
            return ExitCode.fetchFailed.rawValue
        case .refused(let label, let reason):
            output("threatmodeller: \(label): \(reason)")
            return ExitCode.didNotParse.rawValue
        case .notAProject(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.fileFault.rawValue
        }
    }

    private func remove(
        label: String,
        root: String,
        isForced: Bool,
        output: (String) -> Void
    ) -> Int32 {
        switch RemoveLibrary(projects: projects, architectureSources: architecture).execute(
            RemoveLibraryRequest(root: root, label: label, isForced: isForced)
        ) {
        case .removed(let files):
            output("\(label): removed \(files.joined(separator: ", "))")
            return ExitCode.success.rawValue
        case .inUse(let systems):
            output(
                "threatmodeller: these systems still name a technology \"\(label)\" "
                    + "defines: \(systems.joined(separator: ", ")). "
                    + "Use --force to remove it anyway."
            )
            return ExitCode.unanswered.rawValue
        case .noSuchLibrary:
            output("threatmodeller: this project holds no library called \"\(label)\"")
            return ExitCode.fileFault.rawValue
        case .notAProject(let reason), .cannotWrite(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.fileFault.rawValue
        }
    }

    private func list(root: String, output: (String) -> Void) -> Int32 {
        switch ListLibraries(
            projects: projects,
            sources: libraries,
            verifies: VerifyLibraries(projects: projects)
        ).execute(ListLibrariesRequest(root: root)) {
        case .listed(let found):
            if found.isEmpty {
                output("threatmodeller: this project holds no library")
            }
            for one in found {
                output(
                    "\(one.label)  \(one.tag)  \(one.repository)  "
                        + (one.matchesLock ? "matches" : "does not match the lock file")
                )
            }
            return ExitCode.success.rawValue
        case .notAProject(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.fileFault.rawValue
        }
    }

    private func verify(root: String, output: (String) -> Void) -> Int32 {
        switch VerifyLibraries(projects: projects).execute(VerifyLibrariesRequest(root: root)) {
        case .verified(let matched, let differed):
            for fileName in matched { output("\(fileName): matches the lock file") }
            for fileName in differed { output("\(fileName): does not match the lock file") }
            if matched.isEmpty && differed.isEmpty {
                output("threatmodeller: this project holds no library")
            }
            return differed.isEmpty
                ? ExitCode.success.rawValue
                : ExitCode.unanswered.rawValue
        case .notAProject(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.fileFault.rawValue
        }
    }

    private func outdated(root: String, output: (String) -> Void) -> Int32 {
        switch ListOutdatedLibraries(projects: projects, fetcher: fetcher).execute(
            ListOutdatedLibrariesRequest(root: root)
        ) {
        case .listed(let found):
            var isBehind = false
            for one in found {
                if let newest = one.newestTag {
                    isBehind = true
                    output("\(one.label): \(one.tag) is vendored; \(newest) is newer")
                } else if let reason = one.reason {
                    output("\(one.label): \(one.tag) is vendored; the tags could not be read: \(reason)")
                } else {
                    output("\(one.label): \(one.tag) is the newest")
                }
            }
            if found.isEmpty { output("threatmodeller: this project holds no library") }
            return isBehind ? ExitCode.unanswered.rawValue : ExitCode.success.rawValue
        case .notAProject(let reason):
            output("threatmodeller: \(reason)")
            return ExitCode.fileFault.rawValue
        }
    }

    private func read(_ path: String, _ output: (String) -> Void) -> String? {
        do {
            return try projects.read(path: path)
        } catch {
            output("threatmodeller: \(Self.described(error))")
            return nil
        }
    }

    private static func described(_ error: Error) -> String {
        switch error {
        case ProjectError.notADirectory(let path): "\(path) is not a directory"
        case ProjectError.cannotRead(let path, let reason): "cannot read \(path): \(reason)"
        case ProjectError.cannotWrite(let path, let reason): "cannot write \(path): \(reason)"
        default: String(describing: error)
        }
    }

    static let usage = """
    Craig's Threat Modeller — the code-first threat modeller

    Usage:
      threatmodeller compile [<root>]  write or merge every .controls file
      threatmodeller check   [<root>]  say what has no answer, and exit 1 if any has none
      threatmodeller history [<root>]  say what the model scored at each sampled commit
      threatmodeller report  [<root>]  write every .md report
      threatmodeller draw    [<root>]  write every diagram as a picture
      threatmodeller export  [<root>]  write every model as data another program reads
      threatmodeller list    [<root>]  say what each system holds and what it scores
      threatmodeller lsp               speak the Language Server Protocol on standard
                                       input and output
      threatmodeller mcp     [<root>]  serve the Model Context Protocol on standard
                                       input and output
      threatmodeller import terraform [<root>]  draw what a Terraform state holds,
                                       reading `terraform show -json` on standard input
      threatmodeller format  [<root>]  rewrite every .arch, .attacktree and .lib file
                                       in the canonical shape
      threatmodeller help              show this text

    Shared element libraries:
      threatmodeller library add <repository> <tag> [<root>]  fetch and pin a library
      threatmodeller library update [<label>] [<root>]        fetch again at the recorded tag
      threatmodeller library remove <label> [<root>]          delete a library and its lock entry
      threatmodeller library list [<root>]                    say what this project holds
      threatmodeller library verify [<root>]                  check the files against the lock file
      threatmodeller library outdated [<root>]                say which libraries have a newer tag

      threatmodeller split <system> [<root>]                  move a flat system into a directory

      threatmodeller attack sync [<tag>] [<root>]             download and extract MITRE ATT&CK
      threatmodeller attack verify [<root>]                   check this machine against the lock file
      threatmodeller actors list [--mitre] [<root>]           say what actors this project may face

    Options:
      -o <dir>              write the reports into this directory
      --html                write the report as one page as well, pictures and all
      --svg                 draw as SVG, which every build writes
      --png                 draw as PNG, which only a macOS build writes
      --mermaid             draw as Mermaid text, which a wiki renders
      --dot                 draw as Graphviz DOT text
      --d2                  draw as D2 text
      --diagram <language>  report writes the diagram as text: mermaid
      --template <file>     report renders through this template
      --catalogue <dir>     read the threat catalogue from this directory
      --tolerance <level>   a likelihood finding answers a threat up to this level
      --format <name>       plain, github or json; check, compile and format read it.
                            export reads json or otm, the shape it writes
      --stdout              export writes one system to standard output
      --fields <a,b,c>      list writes these columns, in this order
      --sort <field>        list orders the rows by this column
      --no-header           list writes no header row
      --json                list writes the rows as an array a dashboard reads
      --allow-writes        mcp offers the two tools that write a file
      --commits <n>         how many commits history samples, newest first
      -q, --quiet           say nothing about a file that did not change
      -f, --force           remove a library a system still names

    add, update and outdated run `git`, so they use the access a person
    already has: their ssh-agent, their ~/.ssh/config and their credential
    helper. This application holds no credential of its own. verify runs no
    child process and reaches no server.

    <root> is the project root, and defaults to the working directory. This
    application reads <root>/threatmodel when that directory exists, and <root>
    when it does not.

    Exit codes: 0 success; 1 a threat is unanswered, a library file does not
    match the lock file, a library a system names was not removed, or a library
    has a newer tag; 2 a file did not parse; 3 a file could not be read or
    written; 4 a library could not be fetched.
    """
}
