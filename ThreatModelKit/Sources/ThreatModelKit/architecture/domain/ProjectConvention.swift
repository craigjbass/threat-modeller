/// The rule that pairs an architecture file with its answers and its report.
///
/// Every gateway uses this, so the fake and the real one cannot pair files
/// differently.
public enum ProjectConvention {
    public static let architectureExtension = "arch"
    public static let controlsExtension = "controls"
    public static let reportExtension = "md"

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
                    reportPath: path(directory, "\(name).\(reportExtension)")
                )
            }
            .sorted { $0.name < $1.name }
    }

    public static func path(_ directory: String, _ fileName: String) -> String {
        directory.hasSuffix("/") ? "\(directory)\(fileName)" : "\(directory)/\(fileName)"
    }
}
