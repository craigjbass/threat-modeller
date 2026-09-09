import ArchitectureDSL
import CatalogueGateways
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
    }

    private let projects: ProjectSourceGateway
    private let architecture: ArchitectureSourceGateway
    private let controls: ControlsSourceGateway
    /// Built once a catalogue is known, which is only when a verb needs one.
    private let makeCatalogue: () throws -> TechnologyCatalogue

    public init(
        projects: ProjectSourceGateway,
        architecture: ArchitectureSourceGateway = HclArchitectureSource(),
        controls: ControlsSourceGateway = HclControlsSource(),
        catalogue: @escaping () throws -> TechnologyCatalogue = { try BundledTechnologyCatalogue() }
    ) {
        self.projects = projects
        self.architecture = architecture
        self.controls = controls
        makeCatalogue = catalogue
    }

    /// `arguments` is `CommandLine.arguments`, so the first one is the
    /// executable's own path.
    public func run(arguments: [String], output: (String) -> Void) -> Int32 {
        var words = Array(arguments.dropFirst())
        var isQuiet = false
        var catalogueDirectory: String?

        var flagless: [String] = []
        var index = 0
        while index < words.count {
            switch words[index] {
            case "--quiet", "-q":
                isQuiet = true
            case "--catalogue":
                index += 1
                catalogueDirectory = index < words.count ? words[index] : nil
            case "-o":
                index += 1
                if index < words.count { flagless.append("-o:" + words[index]) }
            default:
                flagless.append(words[index])
            }
            index += 1
        }
        words = flagless

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
            return format(root: root, isQuiet: isQuiet, output: output)
        case "compile":
            return compile(root: root, isQuiet: isQuiet, output: output)
        case "check":
            return check(root: root, output: output)
        case "report":
            let into = words.first { $0.hasPrefix("-o:") }.map { String($0.dropFirst(3)) }
            return report(root: root, into: into, isQuiet: isQuiet, output: output)
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
    private func format(root: String, isQuiet: Bool, output: (String) -> Void) -> Int32 {
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
            guard written != text else {
                if isQuiet == false { output("unchanged \(system.architecturePath)") }
                continue
            }
            do {
                try projects.write(written, to: system.architecturePath)
                if isQuiet == false { output("formatted \(system.architecturePath)") }
            } catch {
                output("threatmodeller: \(Self.described(error))")
                code = .fileFault
            }
        }
        return code.rawValue
    }

    /// Writes or merges every system's answers.
    private func compile(root: String, isQuiet: Bool, output: (String) -> Void) -> Int32 {
        forEachSystem(root: root, output: output) { system, useCases in
            guard let architectureText = read(system.architecturePath, output) else {
                return .fileFault
            }
            let existing = projects.exists(path: system.controlsPath)
                ? try? projects.read(path: system.controlsPath)
                : nil

            let response = useCases.compileControls().execute(
                CompileControlsRequest(architectureText: architectureText, controlsText: existing)
            )
            guard case .compiled(let text, let answered, let unanswered, let stale) = response else {
                guard case .refused(let diagnostics) = response else { return .didNotParse }
                for diagnostic in diagnostics {
                    output(diagnostic.described(in: system.architecturePath))
                }
                return .didNotParse
            }

            do {
                try projects.write(text, to: system.controlsPath)
            } catch {
                output("threatmodeller: \(Self.described(error))")
                return .fileFault
            }
            if isQuiet == false {
                output(
                    "\(system.controlsPath): \(answered) answered,"
                        + " \(unanswered) unanswered, \(stale) stale"
                )
            }
            return .success
        }
    }

    /// Says what a pull request has not answered.
    private func check(root: String, output: (String) -> Void) -> Int32 {
        forEachSystem(root: root, output: output) { system, useCases in
            guard let architectureText = read(system.architecturePath, output) else {
                return .fileFault
            }
            let existing = projects.exists(path: system.controlsPath)
                ? try? projects.read(path: system.controlsPath)
                : nil

            let response = useCases.checkControlAnswers().execute(
                CheckControlAnswersRequest(architectureText: architectureText, controlsText: existing)
            )
            guard case .checked(let unanswered, let stale, _) = response else {
                guard case .refused(let diagnostics) = response else { return .didNotParse }
                for diagnostic in diagnostics {
                    output(diagnostic.described(in: system.architecturePath))
                }
                return .didNotParse
            }

            for threat in unanswered {
                output("\(system.controlsPath): \(threat.described)")
            }
            for key in stale {
                output("\(system.controlsPath): \(key) is answered but no longer raised")
            }
            if unanswered.isEmpty && stale.isEmpty {
                output("\(system.name): every threat is answered")
                return .success
            }
            return .unanswered
        }
    }

    /// Writes the Markdown report for every system.
    private func report(
        root: String,
        into: String?,
        isQuiet: Bool,
        output: (String) -> Void
    ) -> Int32 {
        forEachSystem(root: root, output: output) { system, useCases in
            guard let architectureText = read(system.architecturePath, output) else {
                return .fileFault
            }

            let imported = useCases.importArchitecture()
                .execute(ImportArchitectureRequest(text: architectureText))
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
                if case .refused(let diagnostics) = applied {
                    for diagnostic in diagnostics {
                        output(diagnostic.described(in: system.controlsPath))
                    }
                    return .didNotParse
                }
            }

            let markdown = useCases.exportModelAsMarkdown()
                .execute(ExportModelAsMarkdownRequest())
            let path = into.map { ProjectConvention.path($0, "\(system.name).md") }
                ?? system.reportPath
            do {
                try projects.write(markdown.markdown, to: path)
            } catch {
                output("threatmodeller: \(Self.described(error))")
                return .fileFault
            }
            if isQuiet == false { output("wrote \(path)") }
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
    threatmodeller — the code-first threat modeller

    Usage:
      threatmodeller compile [<root>]  write or merge every .controls file
      threatmodeller check   [<root>]  say what has no answer, and exit 1 if any has none
      threatmodeller report  [<root>]  write every .md report
      threatmodeller format  [<root>]  rewrite every .arch file in the canonical shape
      threatmodeller help              show this text

    Options:
      -o <dir>            write the reports into this directory
      --catalogue <dir>   read the threat catalogue from this directory
      -q, --quiet         say nothing about a file that did not change

    <root> is the project root, and defaults to the working directory. This
    application reads <root>/threatmodel when that directory exists, and <root>
    when it does not.

    Exit codes: 0 success, 1 a threat is unanswered, 2 a file did not parse,
    3 a file could not be read or written.
    """
}
