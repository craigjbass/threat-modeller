import Foundation

/// Where the ATT&CK data sits on this machine.
///
/// A per-user directory, so two projects on one machine share one copy and
/// nobody commits somebody else's data. `THREATMODELLER_ATTACK_DIR` overrides
/// it, which is what a test and a build machine use.
public enum AttackDataLocation {
    public static let groupsFileName = "groups.json"
    public static let techniquesFileName = "techniques.json"

    /// The directory, by the rule the design states.
    public static func directory(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        home: String = NSHomeDirectory()
    ) -> String {
        if let stated = environment["THREATMODELLER_ATTACK_DIR"], stated.isEmpty == false {
            return stated
        }
        #if os(macOS)
        return "\(home)/Library/Application Support/threatmodeller/attack"
        #else
        if let data = environment["XDG_DATA_HOME"], data.isEmpty == false {
            return "\(data)/threatmodeller/attack"
        }
        return "\(home)/.local/share/threatmodeller/attack"
        #endif
    }
}

/// Which ATT&CK release the application takes when nobody names one.
public enum AttackRelease {
    /// The tag the application offers. A person names another.
    public static let `default` = "v19.2"
    public static let repository = "mitre-attack/attack-stix-data"
    /// About this many bytes, so a person knows what they are starting.
    public static let bundleBytes = 53_835_637

    /// Where the bundle of one tag is.
    public static func address(of tag: String) -> String {
        let version = tag.hasPrefix("v") ? String(tag.dropFirst()) : tag
        return "https://raw.githubusercontent.com/\(repository)/\(tag)"
            + "/enterprise-attack/enterprise-attack-\(version).json"
    }

    /// What the bundle is called inside the release.
    public static func bundlePath(of tag: String) -> String {
        let version = tag.hasPrefix("v") ? String(tag.dropFirst()) : tag
        return "enterprise-attack/enterprise-attack-\(version).json"
    }
}
