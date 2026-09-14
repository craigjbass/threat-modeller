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
    private let fetcher: LibraryFetching
    /// Built once a catalogue is known, which is only when a verb needs one.
    private let makeCatalogue: () throws -> TechnologyCatalogue

    public init(
        projects: ProjectSourceGateway,
        architecture: ArchitectureSourceGateway = HclArchitectureSource(),
        controls: ControlsSourceGateway = HclControlsSource(),
        attackTrees: AttackTreeSourceGateway = HclAttackTreeSource(),
        libraries: LibrarySourceGateway = HclLibrarySource(),
        fetcher: LibraryFetching = GitLibraryFetcher(),
        catalogue: @escaping () throws -> TechnologyCatalogue = { try BundledTechnologyCatalogue() }
    ) {
        self.projects = projects
        self.architecture = architecture
        self.controls = controls
        self.attackTrees = attackTrees
        self.libraries = libraries
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
            case "--format":
                index += 1
                let named = index < words.count ? words[index] : ""
                if let format = MachineOutput.named(named) {
                    machineOutput = format
                } else {
                    unknownFormat = named
                }
            case "--svg":
                pictures.insert(.svg)
            case "--png":
                pictures.insert(.png)
            case "--html":
                wantsHtml = true
            case "-o":
                index += 1
                if index < words.count { flagless.append("-o:" + words[index]) }
            default:
                flagless.append(words[index])
            }
            index += 1
        }
        words = flagless

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
        case "library":
            return library(words: Array(words.dropFirst()), isForced: isForced, output: output)
        case "report":
            let into = words.first { $0.hasPrefix("-o:") }.map { String($0.dropFirst(3)) }
            return report(
                root: root,
                into: into,
                wantsHtml: wantsHtml,
                isQuiet: isQuiet,
                output: output
            )
        case "draw":
            let into = words.first { $0.hasPrefix("-o:") }.map { String($0.dropFirst(3)) }
            return draw(root: root, into: into, wants: pictures, isQuiet: isQuiet, output: output)
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

        if layout.systems.isEmpty {
            output("threatmodeller: \(layout.directory) holds no .arch files")
            return ExitCode.success.rawValue
        }

        var code = ExitCode.success
        for system in layout.systems {
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

            let response = useCases.compileControls().execute(
                CompileControlsRequest(
                    architectureText: architectureText,
                    controlsText: existing,
                    attackTreeText: treeText(of: system)
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
                try projects.write(text, to: system.controlsPath)
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

        let code = forEachSystem(root: root, output: say) { system, useCases in
            guard let architectureText = read(system.architecturePath, say) else {
                return .fileFault
            }
            let existing = projects.exists(path: system.controlsPath)
                ? try? projects.read(path: system.controlsPath)
                : nil

            let response = useCases.checkControlAnswers().execute(
                CheckControlAnswersRequest(
                    architectureText: architectureText,
                    controlsText: existing,
                    attackTreeText: treeText(of: system),
                    governanceText: governanceText(of: system),
                    tolerance: tolerance
                )
            )
            guard case .checked(
                let unanswered,
                let stale,
                let staleTrees,
                let governanceFailures,
                let diagnostics,
                let usedTolerance
            ) = response else {
                guard case .refused(let diagnostics) = response else { return .didNotParse }
                for diagnostic in diagnostics {
                    switch machineOutput {
                    case .plain:
                        output(diagnostic.described(in: system.architecturePath))
                    case .github:
                        output(GitHubOutput.line(diagnostic, in: system.architecturePath))
                    case .json:
                        messages.append(diagnostic.described(in: system.architecturePath))
                    }
                }
                return .didNotParse
            }

            let unansweredLines = unanswered.map { threat in
                ControlsStanzaLines.line(
                    threatId: threat.threatId,
                    sourceKind: threat.sourceKind,
                    sourceId: threat.sourceId,
                    in: existing
                )
            }

            switch machineOutput {
            case .plain:
                for diagnostic in diagnostics {
                    output(diagnostic.described(in: system.controlsPath))
                }
                for threat in unanswered {
                    output("\(system.controlsPath): \(threat.described)")
                }
                for key in stale {
                    output("\(system.controlsPath): \(key) is answered but no longer raised")
                }
                for described in staleTrees {
                    output("\(system.controlsPath): \(described)")
                }
                for described in governanceFailures {
                    output("\(system.governancePath): \(described)")
                }
                output("\(system.name): checked against a \(usedTolerance) risk tolerance")
                if unanswered.isEmpty && stale.isEmpty && staleTrees.isEmpty
                    && governanceFailures.isEmpty {
                    output("\(system.name): every threat is answered")
                }
            case .github:
                for diagnostic in diagnostics {
                    output(GitHubOutput.line(diagnostic, in: system.controlsPath))
                }
                for (threat, line) in zip(unanswered, unansweredLines) {
                    output(
                        GitHubOutput.line(
                            severity: .error,
                            file: system.controlsPath,
                            line: line,
                            column: 1,
                            message: threat.described
                        )
                    )
                }
                for key in stale {
                    output(
                        GitHubOutput.line(
                            severity: .error,
                            file: system.controlsPath,
                            line: 1,
                            column: 1,
                            message: "\(key) is answered but no longer raised"
                        )
                    )
                }
                for described in staleTrees {
                    output(
                        GitHubOutput.line(
                            severity: .error,
                            file: system.controlsPath,
                            line: 1,
                            column: 1,
                            message: described
                        )
                    )
                }
                for described in governanceFailures {
                    output(
                        GitHubOutput.line(
                            severity: .error,
                            file: system.governancePath,
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
                    name: system.name,
                    tolerance: usedTolerance,
                    diagnostics: diagnostics.map {
                        CheckedSystemJSON.DiagnosticJSON(
                            severity: $0.severity.rawValue,
                            file: system.controlsPath,
                            line: $0.line,
                            column: $0.column,
                            message: $0.message
                        )
                    },
                    unanswered: zip(unanswered, unansweredLines).map { threat, line in
                        CheckedSystemJSON.UnansweredJSON(
                            threatId: threat.threatId,
                            sourceKind: threat.sourceKind,
                            sourceId: threat.sourceId,
                            riskLevel: threat.riskLevel,
                            file: system.controlsPath,
                            line: line
                        )
                    },
                    stale: stale,
                    staleTrees: staleTrees,
                    governance: governanceFailures
                )
            )

            if unanswered.isEmpty && stale.isEmpty && staleTrees.isEmpty
                && governanceFailures.isEmpty {
                return .success
            }
            return .unanswered
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
        wantsHtml: Bool,
        isQuiet: Bool,
        output: (String) -> Void
    ) -> Int32 {
        forEachSystem(root: root, output: output) { system, useCases in
            guard let architectureText = read(system.architecturePath, output) else {
                return .fileFault
            }

            let imported = useCases.importArchitecture()
                .execute(
                    ImportArchitectureRequest(
                        text: architectureText,
                        attackTreeText: treeText(of: system)
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

            // A picture of each of the top residual threats, beside the
            // report. The core cannot draw one: drawing depends on the core.
            let report = useCases.buildThreatModelReport()
                .execute(BuildThreatModelReportRequest()).report
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

            let threatPictures = Dictionary(
                uniqueKeysWithValues: pictures.map { ($0.key, $0.fileName) }
            )
            let controlPictures = Dictionary(
                uniqueKeysWithValues: controls.map { ($0.protectorId, $0.fileName) }
            )
            let markdown = useCases.exportModelAsMarkdown()
                .execute(
                    ExportModelAsMarkdownRequest(
                        threatPictures: threatPictures,
                        controlPictures: controlPictures
                    )
                )
            let path = into.map { ProjectConvention.path($0, "\(system.name).md") }
                ?? system.reportPath
            let beside = String(path.dropLast("\(system.name).md".count))

            for picture in pictures {
                do {
                    try projects.write(picture.svg, to: beside + picture.fileName)
                } catch {
                    output("threatmodeller: \(Self.described(error))")
                    return .fileFault
                }
            }
            for picture in controls {
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
                        wholePicture: SvgWriter.svg(of: DiagramBuilder.drawing(of: drawn))
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
    }

    /// Writes every system as a picture.
    ///
    /// SVG is written by this package, so it works wherever the tool runs. PNG
    /// needs a drawing engine, which only Apple's platforms supply here, so a
    /// Linux build says so rather than writing nothing.
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
                        attackTreeText: treeText(of: system)
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
            let drawing = DiagramBuilder.drawing(
                of: DiagramBuilder.Model(
                    components: canvas.components,
                    connections: canvas.connections,
                    zones: canvas.zones,
                    risks: ElementRiskRollup.byElement(
                        assessment.threats,
                        levelOrder: assessment.severities.map(\.id)
                    ),
                    guards: EdgeGuards.byElement(assessment.threats)
                )
            )

            for format in formats.sorted(by: { $0.rawValue < $1.rawValue }) {
                let name = "\(system.name).\(format.rawValue)"
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
                architectureSources: architecture,
                controlsSources: controls
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
      threatmodeller report  [<root>]  write every .md report
      threatmodeller draw    [<root>]  write every diagram as a picture
      threatmodeller format  [<root>]  rewrite every .arch file in the canonical shape
      threatmodeller help              show this text

    Shared element libraries:
      threatmodeller library add <repository> <tag> [<root>]  fetch and pin a library
      threatmodeller library update [<label>] [<root>]        fetch again at the recorded tag
      threatmodeller library remove <label> [<root>]          delete a library and its lock entry
      threatmodeller library list [<root>]                    say what this project holds
      threatmodeller library verify [<root>]                  check the files against the lock file
      threatmodeller library outdated [<root>]                say which libraries have a newer tag

    Options:
      -o <dir>              write the reports into this directory
      --html                write the report as one page as well, pictures and all
      --svg                 draw as SVG, which every build writes
      --png                 draw as PNG, which only a macOS build writes
      --catalogue <dir>     read the threat catalogue from this directory
      --tolerance <level>   a likelihood finding answers a threat up to this level
      --format <name>       plain, github or json; check, compile and format read it
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
