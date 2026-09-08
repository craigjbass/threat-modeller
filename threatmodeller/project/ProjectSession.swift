import Observation
import ThreatModelKit

/// Holds which project is open, which system is drawn, and what the last read
/// said about the files.
///
/// It owns no rules. Every answer comes from a use case.
@MainActor
@Observable
final class ProjectSession {
    private let useCases: UseCaseFactory

    private(set) var root: String?
    private(set) var directory: String?
    private(set) var systems: [String] = []
    private(set) var chosenSystem: String?
    /// What the last read of a file said. Errors stop a system being drawn;
    /// warnings do not.
    private(set) var diagnostics: [Diagnostic] = []
    /// The file the diagnostics belong to, for the sheet's heading.
    private(set) var diagnosticsFileName: String?
    private(set) var errorMessage: String?
    /// How many threats the last save left with no answer.
    private(set) var unansweredThreats = 0
    /// Where the last report was written.
    private(set) var reportPath: String?

    /// The session drawing the chosen system, or nil while nothing is drawn.
    private(set) var model: ThreatModelSession?

    init(useCases: UseCaseFactory) {
        self.useCases = useCases
    }

    var hasErrors: Bool {
        diagnostics.contains { $0.severity == .error }
    }

    /// Opens a project root and draws its first system.
    func open(root: String) {
        switch useCases.openProject().execute(OpenProjectRequest(root: root)) {
        case .opened(let systems, let directory):
            self.root = root
            self.directory = directory
            self.systems = systems
            errorMessage = systems.isEmpty
                ? "\(directory) holds no .arch files."
                : nil
            if let first = systems.first { choose(first) }
        case .notAProject(let reason):
            self.root = nil
            systems = []
            model = nil
            errorMessage = "That is not a project: \(reason)"
        }
    }

    /// Draws one system. A file with a fault draws nothing and fills the
    /// diagnostics, because half a diagram is worse than none.
    func choose(_ systemName: String) {
        guard let root else { return }

        switch useCases.openSystem().execute(
            OpenSystemRequest(root: root, systemName: systemName)
        ) {
        case .opened(_, let warnings):
            chosenSystem = systemName
            diagnostics = warnings
            diagnosticsFileName = "\(systemName).arch"
            errorMessage = nil
            model = ThreatModelSession(useCases: useCases)
        case .refused(let fileName, let faults):
            chosenSystem = systemName
            diagnostics = faults
            diagnosticsFileName = fileName
            model = nil
            errorMessage = "\(fileName) did not parse."
        case .noSuchSystem:
            errorMessage = "This project no longer holds \"\(systemName)\"."
        case .cannotRead(let reason):
            errorMessage = "That system could not be read: \(reason)"
        }
    }

    /// Writes the drawn system back to the file it came from, and merges the
    /// answers on screen into its controls file.
    func save() {
        guard let root, let chosenSystem else { return }

        switch useCases.saveSystem().execute(
            SaveSystemRequest(root: root, systemName: chosenSystem)
        ) {
        case .saved:
            errorMessage = nil
            saveAnswers(root: root, systemName: chosenSystem)
        case .noSuchSystem:
            errorMessage = "This project no longer holds \"\(chosenSystem)\"."
        case .cannotWrite(let reason):
            errorMessage = "That system could not be written: \(reason)"
        }
    }

    private func saveAnswers(root: String, systemName: String) {
        switch useCases.saveSystemAnswers().execute(
            SaveSystemAnswersRequest(root: root, systemName: systemName)
        ) {
        case .saved(_, _, let unanswered, _):
            unansweredThreats = unanswered
        case .noSuchSystem:
            errorMessage = "This project no longer holds \"\(systemName)\"."
        case .refused(let faults):
            diagnostics = faults
            diagnosticsFileName = "\(systemName).controls"
            errorMessage = "\(systemName).controls did not parse."
        case .cannotWrite(let reason):
            errorMessage = "The answers could not be written: \(reason)"
        }
    }

    /// Writes the Markdown report for the drawn system.
    func compileReport() {
        guard let root, let chosenSystem else { return }

        switch useCases.compileSystemReport().execute(
            CompileSystemReportRequest(root: root, systemName: chosenSystem)
        ) {
        case .written(let path):
            errorMessage = nil
            reportPath = path
        case .noSuchSystem:
            errorMessage = "This project no longer holds \"\(chosenSystem)\"."
        case .cannotWrite(let reason):
            errorMessage = "The report could not be written: \(reason)"
        }
    }

    func dismissDiagnostics() {
        diagnostics = []
    }
}
