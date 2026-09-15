import SwiftUI
import ThreatModelKit

/// What this application is, and who its data belongs to.
///
/// Spec section 7 sets the licence obligations: a `NOTICE` file, both
/// attributions surfaced here, and the vendored catalogue's repository and
/// release tag recorded in this window.
struct AboutWindow: View {
    let catalogue: ViewCatalogueVersionResponse?
    /// What build this is. A test states what the window shows by passing one
    /// rather than by building a bundle.
    var version: AboutVersion = .ofThisBundle
    /// The libraries the open project reads, each with its repository and its
    /// tag. Empty means the project reads none, and the window says so.
    var libraries: [ListedLibrary] = []
    /// The ATT&CK data this machine holds, or nil when nothing could ask.
    /// `.nothingHeld` and nil both mean the machine holds none.
    var attack: ViewAttackDataResponse?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 14) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 48))
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Craig's Threat Modeller")
                        .font(.title2.bold())
                    Text(version.described)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("about-version")
                    if let releaseName = version.releaseName {
                        Text(releaseName)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                            .accessibilityIdentifier("about-release-name")
                    }
                    Text("Copyright © 2026 Craig J. Bass. MIT licence.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Divider()

            VStack(alignment: .leading, spacing: 6) {
                Text("Threat catalogue")
                    .font(.headline)
                if let catalogue {
                    Text("\(catalogue.repository) \(catalogue.tag)")
                        .font(.callout)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("about-catalogue-tag")
                    Text("\(catalogue.technologyCount) technologies")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Text("The catalogue could not be loaded.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                // The libraries the project reads, under the catalogue line,
                // so one window states every source of a threat.
                Text("Libraries")
                    .font(.headline)
                    .padding(.top, 6)
                if libraries.isEmpty {
                    Text("This project reads no library.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("about-no-libraries")
                } else {
                    ForEach(libraries, id: \.label) { library in
                        Text("\(library.name) \u{2014} \(library.repository) \(library.tag)")
                            .font(.callout)
                            .textSelection(.enabled)
                            .accessibilityIdentifier("about-library-\(library.label)")
                    }
                }
                Text(
                    "Copyright © 2026 Jack Nelson, licensed under the "
                        + "Creative Commons Attribution 4.0 International Licence (CC BY 4.0)."
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                Link(
                    "creativecommons.org/licenses/by/4.0",
                    destination: URL(string: "https://creativecommons.org/licenses/by/4.0/")!
                )
                .font(.caption)

                // What this machine holds after a synchronise, readable at
                // any time and not for four seconds in the toolbar.
                Text("MITRE ATT&CK")
                    .font(.headline)
                    .padding(.top, 6)
                if case .held(let tag, let groups, let techniques, let writtenAt)? = attack {
                    Text("\(tag) \u{2014} \(groups) groups, \(techniques) techniques")
                        .font(.callout)
                        .textSelection(.enabled)
                        .accessibilityIdentifier("about-attack")
                    if let writtenAt {
                        Text("Written \(writtenAt.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .accessibilityIdentifier("about-attack-written")
                    }
                } else {
                    Text(
                        "This machine holds no ATT&CK data. "
                            + "Synchronise ATT&CK in the project window to download it."
                    )
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("about-no-attack")
                }
            }

            Divider()

            Text(
                "This catalogue includes MITRE ATT&CK® content, reproduced with the permission "
                    + "of The MITRE Corporation. ATT&CK® is a registered trademark of "
                    + "The MITRE Corporation."
            )
            .font(.caption)
            .foregroundStyle(.secondary)

            Spacer(minLength: 0)
        }
        .padding(24)
        .frame(width: 460, height: 480)
        .accessibilityIdentifier("about-window")
    }
}
