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

    public init(
        projects: ProjectSourceGateway,
        architecture: ArchitectureSourceGateway = HclArchitectureSource()
    ) {
        self.projects = projects
        self.architecture = architecture
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
      threatmodeller format [<root>]   rewrite every .arch file in the canonical shape
      threatmodeller help              show this text

    Options:
      --catalogue <dir>   read the threat catalogue from this directory
      -q, --quiet         say nothing about a file that did not change

    <root> is the project root, and defaults to the working directory. This
    application reads <root>/threatmodel when that directory exists, and <root>
    when it does not.

    Exit codes: 0 success, 1 a threat is unanswered, 2 a file did not parse,
    3 a file could not be read or written.
    """
}
