import AppKit
import SwiftUI
import ThreatModelKit

/// Every fault in one file, in the shape an editor and a build log both use.
struct DiagnosticsSheet: View {
    let fileName: String
    let diagnostics: [Diagnostic]
    let dismiss: () -> Void
    /// Where the file is, or nil when the faults belong to no one file. A row
    /// opens the file only when there is one to open.
    var path: String?
    /// The rules the project states for itself, each kept or breached. Empty
    /// for a project with no policy file.
    var policyRules: [ReportPolicyRule] = []
    var workspace: Workspace = SystemWorkspace()
    /// Puts the rows on the pasteboard. A test gives its own.
    var copyToPasteboard: ([String]) -> Void = { lines in
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(lines.joined(separator: "\n"), forType: .string)
    }

    /// Every row as the command line prints it. A fault that names its own
    /// file, which a split system's faults do, names that file.
    var lines: [String] {
        diagnostics.map { "\($0.file ?? path ?? fileName):\($0.line):\($0.column): \($0.message)" }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(fileName)
                .font(.headline)

            Text(says)
                .font(.callout)
                .foregroundStyle(.secondary)

            List {
                ForEach(Array(diagnostics.enumerated()), id: \.offset) { index, diagnostic in
                    row(diagnostic, at: index)
                }
                if policyRules.isEmpty == false {
                    Section("Policy") {
                        ForEach(Array(policyRules.enumerated()), id: \.offset) { index, rule in
                            policyRow(rule, at: index)
                        }
                    }
                }
            }
            .frame(minHeight: 200)

            HStack {
                Button("Copy") { copyToPasteboard(lines) }
                    .accessibilityIdentifier("copy-diagnostics")
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("close-diagnostics")
            }
        }
        .padding(16)
        .frame(width: 560, height: 380)
        .accessibilityIdentifier("diagnostics-sheet")
    }

    /// What the sheet is about to list.
    private var says: String {
        if diagnostics.contains(where: { $0.severity == .error }) {
            return "This file did not parse. Nothing was drawn."
        }
        if diagnostics.isEmpty {
            return "The rules this project enforces, and whether this system keeps them."
        }
        return "This file was drawn. These are the things worth knowing about it."
    }

    /// One rule, marked kept or breached. A breach states the line the check
    /// prints.
    private func policyRow(_ rule: ReportPolicyRule, at index: Int) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: rule.holds ? "checkmark.circle.fill" : "xmark.octagon.fill")
                .foregroundStyle(rule.holds ? Color.green : Color.red)

            VStack(alignment: .leading, spacing: 1) {
                Text(rule.asks)
                Text("\(rule.name): \(rule.holds ? "kept" : "breached")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                ForEach(rule.breaches, id: \.self) { breach in
                    Text("\(rule.name): \(breach)")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }
            Spacer(minLength: 0)
        }
        .accessibilityIdentifier("policy-rule-\(index)")
    }

    /// One fault. Clicking it opens the file it belongs to.
    private func row(_ diagnostic: Diagnostic, at index: Int) -> some View {
        Button {
            guard let path else { return }
            workspace.open(path: path)
        } label: {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(
                    systemName: diagnostic.severity == .error
                        ? "xmark.octagon.fill"
                        : "exclamationmark.triangle.fill"
                )
                .foregroundStyle(diagnostic.severity == .error ? .red : .yellow)

                VStack(alignment: .leading, spacing: 1) {
                    Text(diagnostic.message)
                    Text(
                        "\(diagnostic.file ?? fileName), line \(diagnostic.line), "
                            + "column \(diagnostic.column)"
                    )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(path == nil)
        .accessibilityIdentifier("diagnostic-row-\(index)")
    }
}
