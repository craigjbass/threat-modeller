import Foundation

/// What build this is, read from the bundle.
///
/// The About window states this, and a user quotes it in a bug report, so it
/// has to name the build that shipped rather than the number the project file
/// carries between releases. The release workflow passes the tag into the
/// archive; a build from Xcode carries no release name and states the version
/// alone.
nonisolated struct AboutVersion: Equatable {
    /// `CFBundleShortVersionString`, which the release sets from the tag.
    let version: String
    /// `CFBundleVersion`, which the release sets from the run number.
    let build: String
    /// `TMReleaseName`: the whole tag, including a `-beta-<hash>` suffix a
    /// version number cannot hold. Empty in a build nobody released.
    let releaseName: String?

    init(version: String, build: String, releaseName: String? = nil) {
        self.version = version
        self.build = build
        self.releaseName = releaseName
    }

    init(_ info: [String: Any]?) {
        func text(_ key: String) -> String? {
            guard let value = info?[key] as? String else { return nil }
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty ? nil : trimmed
        }

        version = text("CFBundleShortVersionString") ?? "1.0"
        build = text("CFBundleVersion") ?? "1"
        releaseName = text("TMReleaseName")
    }

    static var ofThisBundle: AboutVersion { AboutVersion(Bundle.main.infoDictionary) }

    var described: String { "Version \(version) (build \(build))" }
}
