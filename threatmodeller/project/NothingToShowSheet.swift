import SwiftUI

/// What a sheet draws when the value it opened for is not there.
///
/// A sheet is a window of its own, presented over this one, and it takes every
/// click in the window while it is up. A sheet body that draws nothing still
/// presents that window: it measures 470 by 80, it draws no pixel, and it
/// holds no control that closes it, so the window under it takes no click, no
/// double click, no drag, no context menu and no keyboard focus. `hitTest` on
/// the window's content view answers the column under the sheet as though
/// nothing were there, which is why #177 read as a covered palette.
///
/// So every sheet in this application draws something. This is what a sheet
/// draws when its value is nil: what is missing, and the one control that
/// closes it.
struct NothingToShowSheet: View {
    /// What is not there, in the words of the thing the person asked for.
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
