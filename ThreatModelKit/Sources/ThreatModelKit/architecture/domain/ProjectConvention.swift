import Foundation

/// The rule that pairs an architecture file with its answers and its report.
///
/// Every gateway uses this, so the fake and the real one cannot pair files
/// differently.
public enum ProjectConvention {
    public static let architectureExtension = "arch"
    public static let controlsExtension = "controls"
    public static let reportExtension = "md"
    public static let attackTreeExtension = "attacktree"
    public static let governanceExtension = "governance"
    /// The directory a project's shared libraries sit in.
    public static let libraryDirectory = "library"
    public static let libraryExtension = "lib"

    /// The systems a directory holds, by name, sorted.
    public static func systems(in directory: String, fileNames: [String]) -> [ProjectSystem] {
        fileNames
            .filter { $0.hasSuffix(".\(architectureExtension)") }
            .map { fileName in
                let name = String(fileName.dropLast(architectureExtension.count + 1))
                return ProjectSystem(
                    name: name,
                    architecturePath: path(directory, "\(name).\(architectureExtension)"),
                    controlsPath: path(directory, "\(name).\(controlsExtension)"),
                    reportPath: path(directory, "\(name).\(reportExtension)"),
                    attackTreePath: path(directory, "\(name).\(attackTreeExtension)"),
                    governancePath: path(directory, "\(name).\(governanceExtension)")
                )
            }
            .sorted { $0.name < $1.name }
    }

    /// The library files a directory holds, sorted, so two reads of one
    /// project list the same thing.
    public static func libraries(in directory: String, fileNames: [String]) -> [String] {
        fileNames
            .filter { $0.hasSuffix(".\(libraryExtension)") }
            .sorted()
            .map { path(directory, $0) }
    }

    /// The file stem a system with this name is written under.
    ///
    /// A project lists its systems by file name, so a name the user types has
    /// to become one file name and always the same one. Letters and digits
    /// stay, lower case; everything else becomes a single hyphen, and a
    /// hyphen never starts or ends the stem.
    public static func fileName(forSystemNamed name: String) -> String {
        var stem = ""
        var pendingHyphen = false

        for character in name.lowercased() {
            if character.isLetter || character.isNumber {
                if pendingHyphen && stem.isEmpty == false { stem.append("-") }
                pendingHyphen = false
                stem.append(character)
            } else {
                pendingHyphen = true
            }
        }

        return stem
    }

    /// The project a file belongs to, and the system it names, or nil when
    /// this application does not read that file.
    ///
    /// A user double-clicks a system's file and means "open this system". The
    /// application opens projects, not files, so a file has to say which
    /// project holds it. A system's files sit in the convention directory, and
    /// `discover` also allows a project that keeps them in its root, so both
    /// arrangements resolve here.
    public static func system(atPath path: String) -> (root: String, systemName: String)? {
        let file = path as NSString
        let fileExtension = file.pathExtension
        guard fileExtension == architectureExtension
            || fileExtension == controlsExtension
            || fileExtension == attackTreeExtension
            || fileExtension == governanceExtension
        else {
            return nil
        }

        let directory = file.deletingLastPathComponent
        guard directory.isEmpty == false, directory != "/" else { return nil }

        let root = (directory as NSString).lastPathComponent == conventionDirectoryName
            ? (directory as NSString).deletingLastPathComponent
            : directory
        guard root.isEmpty == false else { return nil }

        return (root: root, systemName: (file.deletingPathExtension as NSString).lastPathComponent)
    }

    /// The directory a project keeps its systems in. `ProjectSourceGateway`
    /// states the same name; this copy is here because the rule that reads a
    /// path cannot reach a gateway.
    static let conventionDirectoryName = "threatmodel"

    public static func path(_ directory: String, _ fileName: String) -> String {
        directory.hasSuffix("/") ? "\(directory)\(fileName)" : "\(directory)/\(fileName)"
    }
}
