import SwiftUI

/// What a Terraform import wrote, in the words `threatmodeller import
/// terraform` prints for it: one line per added or removed element, one line
/// for the resource types this application does not map, and a summary line
/// naming the file.
struct TerraformImportSheet: View {
    let result: TerraformImportResult
    let dismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Import from Terraform")
                .font(.headline)

            Text(result.path)
                .font(.callout)
                .foregroundStyle(.secondary)
                .accessibilityIdentifier("terraform-import-path")

            if result.lines.isEmpty {
                ContentUnavailableView(
                    "Nothing changed",
                    systemImage: "checkmark.circle",
                    description: Text("The state holds nothing new to draw.")
                )
                .frame(minHeight: 160)
            } else {
                List(Array(result.lines.enumerated()), id: \.offset) { _, line in
                    Text(line)
                        .accessibilityIdentifier("terraform-import-line")
                }
                .frame(minHeight: 160)
                .accessibilityIdentifier("terraform-import-lines")
            }

            HStack {
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .accessibilityIdentifier("close-terraform-import")
            }
        }
        .padding(16)
        .frame(width: 520, height: 380)
        .accessibilityIdentifier("terraform-import-sheet")
    }
}
