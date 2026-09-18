import SwiftUI

/// What a sheet draws when the value it opened for is not there.
struct NothingToShowSheet: View {
    let says: String
    let dismiss: () -> Void

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "questionmark.circle")
                .font(.system(size: 34))
                .foregroundStyle(.secondary)

            Text(says)
                .font(.callout)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 360)

            Button("Close", action: dismiss)
                .keyboardShortcut(.defaultAction)
                .accessibilityIdentifier("close-nothing-to-show")
        }
        .padding(28)
        .frame(minWidth: 380)
        .accessibilityIdentifier("nothing-to-show")
    }
}
