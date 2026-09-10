import SwiftUI
import ThreatModelKit

/// What this application is, and who its data belongs to.
///
/// Spec section 7 sets the licence obligations: a `NOTICE` file, both
/// attributions surfaced here, and the vendored catalogue's repository and
/// release tag recorded in this window.
struct AboutWindow: View {
    let catalogue: ViewCatalogueVersionResponse?

    private var version: String {
        let short = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return "Version \(short) (\(build))"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 14) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 48))
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Craig's Threat Modeller")
                        .font(.title2.bold())
                    Text(version)
                        .font(.callout)
                        .foregroundStyle(.secondary)
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
        .frame(width: 460, height: 400)
        .accessibilityIdentifier("about-window")
    }
}
