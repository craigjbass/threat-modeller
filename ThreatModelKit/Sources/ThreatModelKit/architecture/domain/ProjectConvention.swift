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
    /// The rules a project states for itself, one file for the whole project.
    public static let policyFileName = "policy.hcl"
    /// The directory a project's shared libraries sit in.
    public static let libraryDirectory = "library"
    /// The index this application reads when nobody names another. It is a
    /// git repository holding one `index.json`, as the library index design
    /// states.
    public static let defaultLibraryIndex = "https://github.com/craigjbass/threat-modeller"
    public static let libraryExtension = "lib"

    /// The directory inside a subproject that holds each kind of file. The
    /// name states the extension: `arch` holds `.arch`.
    public static func kindDirectory(_ fileExtension: String) -> String { fileExtension }

    /// The systems a project directory holds: the flat ones its files state
    /// and the split ones its subdirectories state.
    ///
    /// `subdirectories` names each directory in the project directory, with
    /// the file names each one holds under each kind directory, keyed by the
    /// kind directory's name.
    public static func systems(
        in directory: String,
        fileNames: [String],
        subdirectories: [String: [String: [String]]] = [:]
    ) -> [ProjectSystem] {
        let flat = systems(in: directory, fileNames: fileNames)

        let split = subdirectories.compactMap { name, kinds -> ProjectSystem? in
            // `library` is the shared library directory, so no system takes
            // that name.
            guard name != libraryDirectory else { return nil }
            let architectures = (kinds[architectureExtension] ?? [])
                .filter { $0.hasSuffix(".\(architectureExtension)") }
                .sorted()
            guard architectures.isEmpty == false else { return nil }

            let subproject = path(directory, name)
            func paths(_ fileExtension: String) -> [String] {
                (kinds[fileExtension] ?? [])
                    .filter { $0.hasSuffix(".\(fileExtension)") }
                    .sorted()
                    .map { path(path(subproject, kindDirectory(fileExtension)), $0) }
            }

            let architecturePaths = architectures.map {
                path(path(subproject, kindDirectory(architectureExtension)), $0)
            }
            // The header file is the one named after the system when the
            // directory holds it, else the first file by name. The merge
            // states which file holds the `system` block; this is the guess a
            // reader makes before anything is parsed.
            let header = architecturePaths.first {
                ProjectSystem.stem(of: $0) == name
            } ?? architecturePaths[0]

            return ProjectSystem(
                name: name,
                architecturePaths: architecturePaths,
                headerPath: header,
                controlsPaths: paths(controlsExtension),
                attackTreePaths: paths(attackTreeExtension),
                reportPath: path(subproject, "\(name).\(reportExtension)"),
                governancePath: path(subproject, "\(name).\(governanceExtension)")
            )
        }

        return (flat + split).sorted { $0.name < $1.name }
    }

    /// The flat systems a directory holds, by name, sorted.
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

    public static func stem(forSystemNamed name: String) -> String {
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

        // A file inside a subproject: `<root>/threatmodel/<system>/arch/edge.arch`.
        // The directory it sits in names the kind, and the one above it names
        // the system.
        let kind = (directory as NSString).lastPathComponent
        if kind == kindDirectory(fileExtension) {
            let subproject = (directory as NSString).deletingLastPathComponent
            let systemName = (subproject as NSString).lastPathComponent
            let above = (subproject as NSString).deletingLastPathComponent
            guard systemName.isEmpty == false, above.isEmpty == false else { return nil }
            let root = (above as NSString).lastPathComponent == conventionDirectoryName
                ? (above as NSString).deletingLastPathComponent
                : above
            guard root.isEmpty == false else { return nil }
            return (root: root, systemName: systemName)
        }

        let root = (directory as NSString).lastPathComponent == conventionDirectoryName
            ? (directory as NSString).deletingLastPathComponent
            : directory
        guard root.isEmpty == false else { return nil }

        return (root: root, systemName: (file.deletingPathExtension as NSString).lastPathComponent)
    }

    /// The directory a project keeps its systems in.
    public static let conventionDirectoryName = "threatmodel"

    public static func path(_ directory: String, _ fileName: String) -> String {
        directory.hasSuffix("/") ? "\(directory)\(fileName)" : "\(directory)/\(fileName)"
    }
}
