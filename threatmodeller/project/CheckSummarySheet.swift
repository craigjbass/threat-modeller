import AppKit
import SwiftUI
import ThreatModelKit

/// Everything `threatmodeller check` would print, in one place.
///
/// One state at the top, then every finding in the words the verb prints,
/// grouped the way it prints them: per system, diagnostics first, then
/// unanswered threats, stale answers, stale trees, and governance.
struct CheckSummarySheet: View {
    let systems: [SystemCheck]
    let dismiss: () -> Void
    /// Puts the lines on the pasteboard. A test gives its own.
    var copyToPasteboard: ([String]) -> Void = { lines in
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(lines.joined(separator: "\n"), forType: .string)
    }

    private var passes: Bool { systems.allSatisfy(\.passes) }
    private var failureCount: Int { systems.reduce(0) { $0 + $1.failureCount } }

    /// Every line as `check` prints it, in the order it prints them.
    var lines: [String] {
        systems.flatMap { system in
            system.findings.map(\.said)
                + [system.toleranceLine].compactMap(\.self)
                + (system.passes ? [system.allAnsweredLine] : [])
        }
    }

    /// The one state: what `threatmodeller check` would exit with, and why.
    var says: String {
        guard passes == false else { return "This project passes check." }
        return failureCount == 1
            ? "This project fails check: 1 finding."
            : "This project fails check: \(failureCount) findings."
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Check")
                .font(.headline)

            HStack(spacing: 6) {
                Image(systemName: passes ? "checkmark.seal.fill" : "xmark.seal.fill")
                    .foregroundStyle(passes ? Color.green : Color.red)
                Text(says)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("check-summary-state")
            }

            if systems.allSatisfy({ $0.findings.isEmpty }) {
                ContentUnavailableView(
                    "This project passes check",
                    systemImage: "checkmark.seal",
                    description: Text(
                        "Every threat is answered, nothing is stale, and every "
                            + "accepted risk has an owner. A pull request run of "
                            + "`threatmodeller check` exits 0."
                    )
                )
                .frame(minHeight: 200)
            } else {
                List {
                    ForEach(systems, id: \.name) { system in
                        Section(system.name) {
                            ForEach(
                                Array(system.findings.enumerated()),
                                id: \.offset
                            ) { index, finding in
                                row(finding, of: system, at: index)
                            }
                            if let toleranceLine = system.toleranceLine {
                                footer(toleranceLine)
                            }
                            if system.passes {
                                footer(system.allAnsweredLine)
                            }
                        }
                    }
                }
                .frame(minHeight: 200)
            }

            HStack {
                Button("Copy") { copyToPasteboard(lines) }
                    .accessibilityIdentifier("copy-check-summary")
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("close-check-summary")
            }
        }
        .padding(16)
        .frame(width: 640, height: 420)
        .accessibilityIdentifier("check-summary-sheet")
    }

    /// One finding, in the words the verb prints, with its group named. A
    /// diagnostic on a parsed system is a warning and does not fail the
    /// check; everything else does.
    private func row(_ finding: CheckFinding, of system: SystemCheck, at index: Int) -> some View {
        let warns = finding.category == .diagnostic && system.didParse
        return HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: symbol(of: finding.category))
                .foregroundStyle(warns ? Color.yellow : Color.red)

            VStack(alignment: .leading, spacing: 1) {
                Text(finding.said)
                Text(label(of: finding.category))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .accessibilityIdentifier("check-finding-\(system.name)-\(index)")
    }

    /// A line the verb prints that is not a finding: the tolerance, or the
    /// all-answered word.
    private func footer(_ line: String) -> some View {
        Text(line)
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    private func label(of category: CheckFinding.Category) -> String {
        switch category {
        case .diagnostic: "diagnostic"
        case .unanswered: "no answer"
        case .stale: "stale answer"
        case .staleTree: "stale attack tree"
        case .governance: "governance and policy"
        }
    }

    private func symbol(of category: CheckFinding.Category) -> String {
        switch category {
        case .diagnostic: "exclamationmark.triangle.fill"
        case .unanswered: "questionmark.circle.fill"
        case .stale: "clock.badge.xmark"
        case .staleTree: "point.topleft.down.to.point.bottomright.curvepath"
        case .governance: "person.crop.circle.badge.exclamationmark"
        }
    }
}
