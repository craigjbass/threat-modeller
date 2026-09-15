/// A version tag, compared as numbers rather than as text.
///
/// `v10` is newer than `v9`, which sorting text gets wrong. A tag reads as
/// `v?<number>(.<number>)*` with an optional `-<pre-release>` after it, so
/// `v1.2.3` and `2.0` are versions and `latest` is not.
///
/// WARNING: a pre-release is never the newest on its own. A team running
/// `v1.2.0` is not told to move to `v1.3.0-rc.1`; a team already running a
/// pre-release is told about a newer pre-release of the same kind.
public struct TagVersion: Equatable, Comparable, Sendable {
    public let numbers: [Int]
    /// What follows the hyphen, or nil for a release.
    public let preRelease: String?
    /// The tag as the repository states it.
    public let tag: String

    public var isPreRelease: Bool { preRelease != nil }

    /// The tag as a version, or nil when it is not one.
    public init?(_ tag: String) {
        var text = Substring(tag)
        if text.hasPrefix("v") || text.hasPrefix("V") { text = text.dropFirst() }

        var pre: String?
        if let hyphen = text.firstIndex(of: "-") {
            pre = String(text[text.index(after: hyphen)...])
            text = text[..<hyphen]
        }

        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.isEmpty == false else { return nil }
        var numbers: [Int] = []
        for part in parts {
            guard part.isEmpty == false, part.allSatisfy(\.isNumber), let number = Int(part) else {
                return nil
            }
            numbers.append(number)
        }

        self.numbers = numbers
        preRelease = pre
        self.tag = tag
    }

    public static func < (left: TagVersion, right: TagVersion) -> Bool {
        for position in 0 ..< max(left.numbers.count, right.numbers.count) {
            let one = position < left.numbers.count ? left.numbers[position] : 0
            let other = position < right.numbers.count ? right.numbers[position] : 0
            if one != other { return one < other }
        }
        // Same numbers: a pre-release comes before the release it leads to.
        switch (left.preRelease, right.preRelease) {
        case (nil, nil): return false
        case (nil, _): return false
        case (_, nil): return true
        case (let one?, let other?): return one < other
        }
    }

    /// The newest tag of a list, by the rule above, or nil when the list holds
    /// no version.
    ///
    /// `wantsPreRelease` is true when the tag in use is itself a pre-release,
    /// and a pre-release is then eligible.
    public static func newest(of tags: [String], wantsPreRelease: Bool = false) -> String? {
        tags
            .compactMap(TagVersion.init)
            .filter { wantsPreRelease || $0.isPreRelease == false }
            .max()?
            .tag
    }
}
