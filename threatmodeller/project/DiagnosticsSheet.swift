import SwiftUI
import ThreatModelKit

/// Every fault in one file, in the shape an editor and a build log both use.
struct DiagnosticsSheet: View {
    let fileName: String
    let diagnostics: [Diagnostic]
    let dismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(fileName)
                .font(.headline)

            Text(
                diagnostics.contains { $0.severity == .error }
                    ? "This file did not parse. Nothing was drawn."
                    : "This file was drawn. These are the things worth knowing about it."
            )
            .font(.callout)
            .foregroundStyle(.secondary)

            List(Array(diagnostics.enumerated()), id: \.offset) { _, diagnostic in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(
                        systemName: diagnostic.severity == .error
                            ? "xmark.octagon.fill"
                            : "exclamationmark.triangle.fill"
                    )
                    .foregroundStyle(diagnostic.severity == .error ? .red : .yellow)

                    VStack(alignment: .leading, spacing: 1) {
                        Text(diagnostic.message)
                        Text("line \(diagnostic.line), column \(diagnostic.column)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .textSelection(.enabled)
            }
            .frame(minHeight: 200)

            HStack {
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
}
