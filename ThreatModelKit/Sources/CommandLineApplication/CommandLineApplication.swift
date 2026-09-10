import ArchitectureDSL
import CatalogueGateways
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
    private let libraries: LibrarySourceGateway
    private let fetcher: LibraryFetching
    /// Built once a catalogue is known, which is only when a verb needs one.
    private let makeCatalogue: () throws -> TechnologyCatalogue

    public init(
        projects: ProjectSourceGateway,
        architecture: ArchitectureSourceGateway = HclArchitectureSource(),
        controls: ControlsSourceGateway = HclControlsSource(),
        libraries: LibrarySourceGateway = HclLibrarySource(),
        fetcher: LibraryFetching = GitLibraryFetcher(),
        catalogue: @escaping () throws -> TechnologyCatalogue = { try BundledTechnologyCatalogue() }
    ) {
        self.projects = projects
        self.architecture = architecture
        self.controls = controls
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
            return check(root: root, tolerance: tolerance, output: output)
        case "library":
            return library(words: Array(words.dropFirst()), isForced: isForced, output: output)
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
            guard case .compiled(let text, let answered, let unanswered, let stale, let warnings) = response else {
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
            for warning in warnings {
                output(warning.described(in: system.controlsPath))
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
    private func check(root: String, tolerance: String?, output: (String) -> Void) -> Int32 {
        forEachSystem(root: root, output: output) { system, useCases in
            guard let architectureText = read(system.architecturePath, output) else {
                return .fileFault
            }
            let existing = projects.exists(path: system.controlsPath)
                ? try? projects.read(path: system.controlsPath)
                : nil

            let response = useCases.checkControlAnswers().execute(
                CheckControlAnswersRequest(
                    architectureText: architectureText,
                    controlsText: existing,
                    tolerance: tolerance
                )
            )
            guard case .checked(let unanswered, let stale, let diagnostics, let usedTolerance) = response else {
                guard case .refused(let diagnostics) = response else { return .didNotParse }
                for diagnostic in diagnostics {
                    output(diagnostic.described(in: system.architecturePath))
                }
                return .didNotParse
            }

            for diagnostic in diagnostics {
                output(diagnostic.described(in: system.controlsPath))
            }
            for threat in unanswered {
                output("\(system.controlsPath): \(threat.described)")
            }
            for key in stale {
                output("\(system.controlsPath): \(key) is answered but no longer raised")
            }
            output("\(system.name): checked against a \(usedTolerance) risk tolerance")
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
      --catalogue <dir>     read the threat catalogue from this directory
      --tolerance <level>   a likelihood finding answers a threat up to this level
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
