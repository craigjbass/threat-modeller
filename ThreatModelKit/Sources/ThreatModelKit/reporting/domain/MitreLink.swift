/// Where a MITRE ATT&CK technique is written up.
///
/// A technique id is `T1078`, and a sub-technique is `T1550.001`. The address
/// puts the sub-technique in its own path segment, so the dot becomes a
/// slash.
public enum MitreLink {
    public static func address(of techniqueId: String) -> String {
        let path = techniqueId.split(separator: ".", omittingEmptySubsequences: false)
            .joined(separator: "/")
        return "https://attack.mitre.org/techniques/\(path)/"
    }
}
