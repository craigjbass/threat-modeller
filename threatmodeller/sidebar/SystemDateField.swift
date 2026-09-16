import Foundation
import SwiftUI
import ThreatModelKit

/// One date the `system` block states, as a picker and a switch.
///
/// A person picks a day; nobody types one. A typed date can be a text that is
/// not a date, and the parser refuses such a text, so the file would then hold
/// a line the next read reports as an error.
///
/// The switch off writes an empty text, and the writer writes no line: a
/// system that states no `created` date is a system nobody has dated, which is
/// not the same as a system dated today.
struct SystemDateField: View {
    let title: String
    /// `YYYY-MM-DD`, or empty when the system states no date.
    let date: String
    let identifier: String
    let commit: (String) -> Void

    var body: some View {
        HStack(spacing: 6) {
            Toggle(title, isOn: states)
                .font(.caption)
                .accessibilityIdentifier("\(identifier)-states")

            if date.isEmpty {
                Text("no date")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                DatePicker(title, selection: day, displayedComponents: .date)
                    .labelsHidden()
                    .accessibilityIdentifier(identifier)
            }
        }
    }

    private var states: Binding<Bool> {
        Binding(
            get: { date.isEmpty == false },
            set: { on in commit(on ? Self.text(of: Date()) : "") }
        )
    }

    private var day: Binding<Date> {
        Binding(
            get: { Self.day(of: date) ?? Date() },
            set: { commit(Self.text(of: $0)) }
        )
    }

    /// The day a `Date` falls on, in the calendar of the person at the screen.
    /// `CheckGovernance.today(_:)` reads UTC, which is what a report measures a
    /// review interval against, and which is the wrong day for a picker: a
    /// person east of Greenwich picks today and UTC still says yesterday.
    static func text(of date: Date) -> String {
        let parts = Calendar.current.dateComponents([.year, .month, .day], from: date)
        guard let written = GovernanceDate(
            year: parts.year ?? 1970,
            month: parts.month ?? 1,
            day: parts.day ?? 1
        ) else {
            return ""
        }
        return written.description
    }

    /// The `Date` one written day names, at midday so that no time zone moves
    /// it to the day before or the day after.
    static func day(of text: String) -> Date? {
        guard case .success(let read) = GovernanceDate.read(text) else { return nil }
        var parts = DateComponents()
        parts.year = read.year
        parts.month = read.month
        parts.day = read.day
        parts.hour = 12
        return Calendar.current.date(from: parts)
    }
}
