import SwiftUI

/// Puts `threatmodeller` on the user's PATH, or says why it cannot.
///
/// It installs for the person running the application, in their own directory,
/// so it never asks for a password.
struct CommandLineToolSheet: View {
    let tool: CommandLineTool
    let dismiss: () -> Void

    @State private var status: CommandLineTool.Status = .notInThisBuild
    @State private var message: String?
    @State private var didCopy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Command Line Tool")
                .font(.title2)

            Text(
                "threatmodeller compiles, checks and reports a project from a "
                    + "terminal, and manages its shared libraries. It is the same "
                    + "code this window runs."
            )
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            state

            if let message {
                Text(message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("command-line-message")
            }

            Spacer(minLength: 0)

            HStack {
                Spacer()
                buttons
            }
        }
        .padding(24)
        .frame(width: 560, height: 340)
        .onAppear { status = tool.status() }
        .accessibilityIdentifier("command-line-tool-sheet")
    }

    @ViewBuilder
    private var state: some View {
        switch status {
        case .notInThisBuild:
            Label(
                "This build of the application carries no command line tool. "
                    + "Run scripts/embed-cli.sh, or use a release.",
                systemImage: "exclamationmark.triangle"
            )
            .font(.callout)
            .fixedSize(horizontal: false, vertical: true)

        case .notInstalled(let target, let isOnPath):
            VStack(alignment: .leading, spacing: 8) {
                row("Installs to", target)
                row("On your PATH", isOnPath ? "Yes" : "Not yet")
                if isOnPath == false { pathAdvice }
            }

        case .installed(let at, let isCurrent, let isOnPath):
            VStack(alignment: .leading, spacing: 8) {
                Label(
                    isCurrent
                        ? "Installed"
                        : "Installed, but pointing at another copy of the application",
                    systemImage: isCurrent ? "checkmark.circle" : "exclamationmark.triangle"
                )
                .font(.callout)

                row("Command", at)
                row("On your PATH", isOnPath ? "Yes" : "Not yet")
                if isOnPath == false { pathAdvice }
            }
        }
    }

    private func row(_ name: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(name)
                .frame(width: 110, alignment: .leading)
                .foregroundStyle(.secondary)
            Text(value)
                .monospaced()
                .textSelection(.enabled)
                .lineLimit(2)
                .truncationMode(.middle)
        }
        .font(.callout)
    }

    private var pathAdvice: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Add this line to ~/.zshrc, then open a new terminal:")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack {
                Text(tool.pathLine)
                    .monospaced()
                    .font(.caption)
                    .textSelection(.enabled)

                Spacer(minLength: 8)

                Button(didCopy ? "Copied" : "Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(tool.pathLine, forType: .string)
                    didCopy = true
                }
                .accessibilityIdentifier("command-line-copy-path")
            }
            .padding(8)
            .background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
        }
    }

    @ViewBuilder
    private var buttons: some View {
        switch status {
        case .notInThisBuild:
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("command-line-done")

        case .notInstalled:
            Button("Install") { act(tool.install()) }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("command-line-install")
            Button("Cancel") { dismiss() }

        case .installed(_, let isCurrent, _):
            if isCurrent == false {
                Button("Point It Here") { act(tool.install()) }
                    .accessibilityIdentifier("command-line-repair")
            }
            Button("Uninstall") { act(tool.uninstall()) }
                .accessibilityIdentifier("command-line-uninstall")
            Button("Done") { dismiss() }
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("command-line-done")
        }
    }

    private func act(_ outcome: CommandLineTool.Outcome) {
        switch outcome {
        case .installed(let at):
            message = "Written: \(at)"
        case .removed:
            message = "Removed."
        case .refused(let reason):
            message = reason
        }
        didCopy = false
        status = tool.status()
    }
}
