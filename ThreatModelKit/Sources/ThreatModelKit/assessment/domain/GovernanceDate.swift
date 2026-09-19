/// A calendar date, written `YYYY-MM-DD`.
///
/// The governance file states three of them, and a date nobody can read is
/// worse than no date, so the parser refuses anything else. It holds the three
/// numbers rather than a `Date`: a governance date is a day a person wrote,
/// not an instant, and comparing two of them must not depend on a time zone.
public struct GovernanceDate: Equatable, Comparable, Sendable, CustomStringConvertible {
    public let year: Int
    public let month: Int
    public let day: Int

    /// Why a text is not a date.
    public enum Fault: Error, Equatable, Sendable {
        /// The text is not `YYYY-MM-DD` at all.
        case notTheShape
        /// The text is that shape and names no day of the calendar.
        case notADay

        public func message(attribute: String, raw: String) -> String {
            switch self {
            case .notTheShape:
                "\(attribute) is \"\(raw)\"; a date is written YYYY-MM-DD"
            case .notADay:
                "\(attribute) is \"\(raw)\", which is not a date"
            }
        }
    }

    public init?(year: Int, month: Int, day: Int) {
        guard (1...12).contains(month), day >= 1, day <= Self.daysIn(month: month, year: year) else {
            return nil
        }
        self.year = year
        self.month = month
        self.day = day
    }

    /// The date that text writes, or what is wrong with it.
    public static func read(_ raw: String) -> Result<GovernanceDate, Fault> {
        let parts = raw.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 3,
              parts[0].count == 4,
              parts[1].count == 2,
              parts[2].count == 2,
              parts.allSatisfy({ $0.allSatisfy(\.isNumber) }),
              let year = Int(parts[0]),
              let month = Int(parts[1]),
              let day = Int(parts[2]) else {
            return .failure(.notTheShape)
        }
        guard let date = GovernanceDate(year: year, month: month, day: day) else {
            return .failure(.notADay)
        }
        return .success(date)
    }

    public var description: String {
        let month = self.month < 10 ? "0\(self.month)" : "\(self.month)"
        let day = self.day < 10 ? "0\(self.day)" : "\(self.day)"
        return "\(year)-\(month)-\(day)"
    }

    /// The count of days from this date to `other`.
    public func daysUntil(_ other: GovernanceDate) -> Int {
        Self.dayNumber(of: other) - Self.dayNumber(of: self)
    }

    /// The day number of a date, counting from the first of January in year
    /// one. Only the difference of two such numbers is meaningful.
    private static func dayNumber(of date: GovernanceDate) -> Int {
        var days = 0
        for year in 1 ..< date.year { days += isLeap(year) ? 366 : 365 }
        for month in 1 ..< date.month { days += daysIn(month: month, year: date.year) }
        return days + date.day
    }

    public static func < (left: GovernanceDate, right: GovernanceDate) -> Bool {
        (left.year, left.month, left.day) < (right.year, right.month, right.day)
    }

    private static func daysIn(month: Int, year: Int) -> Int {
        switch month {
        case 1, 3, 5, 7, 8, 10, 12: 31
        case 4, 6, 9, 11: 30
        default: isLeap(year) ? 29 : 28
        }
    }

    /// The Gregorian rule: every fourth year, except every hundredth, except
    /// every four hundredth.
    private static func isLeap(_ year: Int) -> Bool {
        (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
    }
}
